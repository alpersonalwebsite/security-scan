import logging
import os
from modules.subprocess_utils import run_subprocess

def run_checkov(target_path, report_path):
    logging.info(f"Running Checkov on {target_path}")
    try:
        # Ensure the directory for the report path exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        command = [
            "checkov", "-d", target_path, "--output", "json", "--output-file-path", report_path
        ]
        result = run_subprocess(command)
        if result is None:
            logging.error("Checkov scan failed due to a subprocess error.")
    except Exception as e:
        logging.exception("Checkov scan failed")
