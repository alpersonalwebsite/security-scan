import logging
import subprocess

def run_grype(target_path, report_path):
    logging.info(f"Running Grype on {target_path}")
    try:
        result = subprocess.run([
            "grype", target_path, "-o", "json"
        ], capture_output=True, text=True)
        with open(report_path, "w") as f:
            f.write(result.stdout)
        if result.returncode != 0:
            logging.warning(f"Grype finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Grype scan failed")
