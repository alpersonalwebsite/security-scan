import json
import logging
import subprocess
import os

def run_hadolint(dockerfile_path, report_path):
    logging.info(f"Running Hadolint on {dockerfile_path}")
    try:
        # Check if the Dockerfile exists
        if not os.path.exists(dockerfile_path):
            logging.warning(f"Dockerfile not found: {dockerfile_path}")
            return

        result = subprocess.run([
            "hadolint", dockerfile_path, "-f", "json"], capture_output=True, text=True)
        try:
            output = json.loads(result.stdout)
            with open(report_path, "w") as f:
                json.dump(output, f, indent=4)
        except json.JSONDecodeError:
            logging.error("Hadolint produced invalid JSON output")
            return
        if not output:
            logging.warning("Hadolint produced empty JSON output")
            return
        if result.returncode != 0:
            logging.warning(f"Hadolint finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Hadolint scan failed")
