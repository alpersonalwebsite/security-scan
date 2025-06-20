import logging
import subprocess
import shutil

def run_gitleaks(target_repo, report_path):
    logging.info(f"Running Gitleaks on {target_repo}")
    
    if not shutil.which("gitleaks"):
        logging.error("Gitleaks is not installed. Please install it and try again.")
        return

    try:
        result = subprocess.run([
            "gitleaks", "detect", "--source", target_repo, "--report-format", "json", "--report-path", report_path
        ], capture_output=True, text=True)
        if result.returncode != 0:
            logging.warning(f"Gitleaks finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Gitleaks scan failed")
