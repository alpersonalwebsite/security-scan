import json
import logging
import os
from modules.subprocess_utils import run_subprocess

def run_hadolint(dockerfile_path, report_path):
    logging.info(f"Running Hadolint on {dockerfile_path}")
    try:
        # Check if the Dockerfile exists
        if not os.path.exists(dockerfile_path):
            logging.warning(f"Dockerfile not found: {dockerfile_path}")
            placeholder = {
                "status": "skipped",
                "reason": "Dockerfile not found"
            }
            with open(report_path, "w") as f:
                json.dump(placeholder, f, indent=4)
            return

        command = [
            "hadolint", dockerfile_path, "-f", "json"
        ]
        result = run_subprocess(command)
        if result and result.stdout:
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
        else:
            logging.error("Hadolint scan failed due to a subprocess error or empty output.")
    except Exception as e:
        logging.exception("Hadolint scan failed")
