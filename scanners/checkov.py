import logging
import subprocess
import os

def run_checkov(target_path, report_path):
    logging.info(f"Running Checkov on {target_path}")
    try:
        # Ensure the report path is a valid file path
        if os.path.isdir(report_path) or not report_path.endswith(".json"):
            report_path = os.path.join(report_path.rstrip('/'), "checkov_report.json")
            logging.warning(f"Adjusted report path to: {report_path}")

        # Ensure the directory for the report path exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)

        result = subprocess.run([
            "checkov", "-d", target_path, "--output", "json", "--output-file-path", report_path
        ], capture_output=True, text=True)
        if result.returncode != 0:
            logging.warning(f"Checkov finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Checkov scan failed")
