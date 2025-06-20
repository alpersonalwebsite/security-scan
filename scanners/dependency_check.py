import logging
import os
from modules.subprocess_utils import run_subprocess

def run_dependency_check(target_path, report_path):
    logging.info(f"Running OWASP Dependency-Check on {target_path}")
    try:
        # Ensure the directory for the report path exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        command = [
            "dependency-check", "--scan", target_path, "--format", "JSON", "--out", report_path
        ]
        result = run_subprocess(command, timeout=600)  # Timeout set to 10 minutes
        if result is None:
            logging.error("Dependency-Check scan failed due to a subprocess error.")
    except Exception as e:
        logging.exception("Dependency-Check scan failed")
