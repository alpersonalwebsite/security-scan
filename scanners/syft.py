import logging
import subprocess

def run_syft(target_path, report_path):
    logging.info(f"Running Syft on {target_path}")
    try:
        result = subprocess.run([
            "syft", target_path, "-o", "json", "-q"
        ], capture_output=True, text=True)
        with open(report_path, "w") as f:
            f.write(result.stdout)
        if result.returncode != 0:
            logging.warning(f"Syft finished with warnings: {result.stderr}")
    except Exception as e:
        logging.exception("Syft scan failed")
