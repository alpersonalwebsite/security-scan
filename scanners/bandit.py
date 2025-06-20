import logging
import subprocess

def run_bandit(target_path, report_path):
    logging.info(f"Running Bandit on {target_path}")
    try:
        result = subprocess.run([
            "bandit", "-r", target_path, "-f", "json", "-o", report_path
        ], capture_output=True, text=True)
        if result.returncode != 0:
            logging.warning(f"Bandit finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Bandit scan failed")
