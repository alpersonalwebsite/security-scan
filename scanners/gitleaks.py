import logging
import shutil
from modules.subprocess_utils import run_subprocess

def run_gitleaks(target_repo, report_path):
    logging.info(f"Running Gitleaks on {target_repo}")
    
    if not shutil.which("gitleaks"):
        logging.error("Gitleaks is not installed. Please install it and try again.")
        return

    try:
        command = [
            "gitleaks", "detect", "--source", target_repo, "--report-format", "json", "--report-path", report_path
        ]
        result = run_subprocess(command)
        if result is None:
            logging.error("Gitleaks scan failed due to a subprocess error.")
    except Exception as e:
        logging.exception("Gitleaks scan failed")
