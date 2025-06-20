import logging
import subprocess

def run_semgrep(target_repo, report_path):
    logging.info(f"Running Semgrep on {target_repo}")
    try:
        result = subprocess.run([
            "semgrep", "--config", "auto", "--json", "--output", report_path, target_repo
        ], capture_output=True, text=True)
        if result.returncode != 0:
            logging.warning(f"Semgrep finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Semgrep scan failed")
