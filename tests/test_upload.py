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
        dossier = self.client.get(f"/api/studies/{study_id}/dossier").json()
        self.assertIn(dossier["riskBand"], {"LOW", "MODERATE", "HIGH"})
        self.assertGreaterEqual(dossier["notesCount"], 1)
        with backend._database() as connection:
            persisted = connection.execute("SELECT payload_json FROM studies WHERE study_id = ?", (study_id,)).fetchone()
        self.assertIn("Reviewed for release workflow.", persisted["payload_json"])

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

    def test_batch_case_management_metadata_and_integrity(self):
        source = backend.STUDIES["ST-44821-CHEST-DX"]["rawFilePath"]
        with open(source, "rb") as first, open(source, "rb") as second:
            response = self.client.post(
                "/api/studies/batch-upload",
                files=[
                    ("files", ("first-study.dcm", first, "application/dicom")),
                    ("files", ("second-study.dcm", second, "application/dicom")),
                ],
            )
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertEqual(payload["acceptedCount"], 2)
        study_id = payload["accepted"][0]["studyId"]
        record = backend.STUDIES[study_id]
        self.created_paths.extend([record["rawFilePath"], record["sandboxedFilePath"]])
        for accepted in payload["accepted"][1:]:
            extra = backend.STUDIES[accepted["studyId"]]
            self.created_paths.extend([extra["rawFilePath"], extra["sandboxedFilePath"]])

        case = self.client.patch(
            f"/api/studies/{study_id}/case",
            json={"priority": "urgent", "owner": "privacy.ops", "dueDate": "2027-01-31", "tags": ["research", "priority"]},
        )
        self.assertEqual(case.status_code, 200)
        self.assertEqual(case.json()["priority"], "URGENT")
        self.assertEqual(case.json()["tags"], ["research", "priority"])
        self.assertEqual(self.client.patch(f"/api/studies/{study_id}/case", json={"tags": "invalid"}).status_code, 400)
        self.assertEqual(self.client.get(f"/api/studies/{study_id}/metadata").status_code, 200)

        self.assertEqual(self.client.post(f"/api/studies/{study_id}/discover").status_code, 200)
        self.assertEqual(self.client.post(f"/api/studies/{study_id}/transform").status_code, 200)
        integrity = self.client.get(f"/api/studies/{study_id}/integrity")
        self.assertEqual(integrity.status_code, 200)
        self.assertEqual(integrity.json()["status"], "VERIFIED")

        filtered = self.client.get("/api/studies", params={"priority": "URGENT", "q": "privacy.ops"}).json()
        self.assertTrue(any(study["id"] == study_id for study in filtered))


if __name__ == "__main__":
    unittest.main()
