import logging
import subprocess
import os

def run_dependency_check(target_path, report_path):
    logging.info(f"Running OWASP Dependency-Check on {target_path}")
    try:
        # Ensure the target path exists
        if not os.path.exists(target_path):
            logging.error(f"Target path does not exist: {target_path}")
            return

        result = subprocess.run([
            "dependency-check", "--scan", target_path, "--format", "JSON", "--out", report_path
        ], capture_output=True, text=True, timeout=600)  # Timeout set to 10 minutes

        if result.returncode != 0:
            logging.warning(f"Dependency-Check finished with warnings: {result.stderr}")
    except subprocess.TimeoutExpired:
        logging.error("Dependency-Check timed out")
    except Exception as e:
        logging.exception("Dependency-Check scan failed")
