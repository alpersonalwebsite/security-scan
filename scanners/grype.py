import logging
from modules.subprocess_utils import run_subprocess

def run_grype(target_path, report_path):
    logging.info(f"Running Grype on {target_path}")
    try:
        command = [
            "grype", target_path, "-o", "json"
        ]
        result = run_subprocess(command)
        if result and result.stdout:
            with open(report_path, "w") as f:
                f.write(result.stdout)
        else:
            logging.error("Grype scan failed due to a subprocess error or empty output.")
    except Exception as e:
        logging.exception("Grype scan failed")
