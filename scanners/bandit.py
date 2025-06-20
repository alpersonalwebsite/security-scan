import logging
from modules.subprocess_utils import run_subprocess

def run_bandit(target_path, report_path):
    logging.info(f"Running Bandit on {target_path}")
    try:
        command = [
            "bandit", "-r", target_path, "-f", "json", "-o", report_path
        ]
        result = run_subprocess(command)
        if result is None:
            logging.error("Bandit scan failed due to a subprocess error.")
    except Exception as e:
        logging.exception("Bandit scan failed")
