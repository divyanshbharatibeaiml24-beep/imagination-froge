import os
import unittest

from fastapi.testclient import TestClient

import backend


class UploadWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(backend.app)
        self.created_paths = []

    def tearDown(self):
        for path in self.created_paths:
            if os.path.exists(path):
                os.remove(path)

    def test_upload_rejects_non_dicom_data(self):
        response = self.client.post(
            "/api/studies/upload",
            files={"file": ("not-a-scan.dcm", b"not a dicom", "application/dicom")},
        )
        self.assertEqual(response.status_code, 422)

    def test_analyst_tools_return_metrics_notes_and_csv(self):
        study_id = "ST-44821-CHEST-DX"
        self.assertEqual(self.client.post(f"/api/studies/{study_id}/discover").status_code, 200)
        self.assertEqual(self.client.post(f"/api/studies/{study_id}/transform").status_code, 200)
        note = self.client.post(f"/api/studies/{study_id}/notes", json={"note": "Reviewed for release workflow."})
        self.assertEqual(note.status_code, 201)
        self.assertEqual(self.client.get(f"/api/studies/{study_id}/findings.csv").headers["content-type"], "text/csv; charset=utf-8")
        metrics = self.client.get("/api/dashboard/metrics").json()
        self.assertGreaterEqual(metrics["studies"], 4)
        self.assertIn("STRICT_RESEARCH_V1", metrics["policyUsage"])

    def test_upload_can_complete_pipeline(self):
        source = backend.STUDIES["ST-44821-CHEST-DX"]["rawFilePath"]
        with open(source, "rb") as handle:
            response = self.client.post(
                "/api/studies/upload",
                files={"file": ("user-scan.dcm", handle, "application/dicom")},
            )
        self.assertEqual(response.status_code, 201)
        study_id = response.json()["studyId"]
        record = backend.STUDIES[study_id]
        self.created_paths.extend([record["rawFilePath"], record["sandboxedFilePath"]])

        self.assertEqual(self.client.post(f"/api/studies/{study_id}/discover").status_code, 200)
        self.assertEqual(
            self.client.post(
                f"/api/studies/{study_id}/transform",
                json={"policyId": "HIPAA_SAFE_HARBOR_EXT"},
            ).status_code,
            200,
        )
        self.client.post(
            f"/api/studies/{study_id}/review/action",
            json={"bulk": True, "action": "approve"},
        )
        for action in ("validate", "attack"):
            self.assertEqual(self.client.post(f"/api/studies/{study_id}/{action}").status_code, 200)

        study = self.client.get(f"/api/studies/{study_id}").json()
        image = self.client.get(f"/api/studies/{study_id}/slice?mode=validated")
        self.assertEqual(study["validationStatus"], "3 / 3 PASS")
        self.assertEqual(study["policyId"], "HIPAA_SAFE_HARBOR_EXT")
        self.assertTrue(study["hashes"]["output"])
        self.assertEqual(image.headers["content-type"], "image/png")
        certificate = self.client.get(f"/api/studies/{study_id}/certificate").json()
        self.assertEqual(certificate["policyId"], "HIPAA_SAFE_HARBOR_EXT")


if __name__ == "__main__":
    unittest.main()
