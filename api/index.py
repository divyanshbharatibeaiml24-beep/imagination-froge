import os
import sys

# Ensure project root directory is on Python path for Vercel Serverless Function runtime
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Import the FastAPI application instance
from backend import app
