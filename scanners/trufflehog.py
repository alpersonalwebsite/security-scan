import json
import logging
import subprocess

def run_trufflehog(target_repo, report_path):
    logging.info(f"Running TruffleHog on {target_repo}")
    try:
        result = subprocess.run([
            "trufflehog", "filesystem", "--json", target_repo
        ], capture_output=True, text=True)
        # Log raw output for debugging
        logging.debug(f"Raw TruffleHog output: {result.stdout}")

        # Save raw output to a file for analysis
        raw_output_path = report_path.replace(".json", "_raw_output.txt")
        with open(raw_output_path, "w") as raw_file:
            raw_file.write(result.stdout)

        if result.returncode != 0:
            logging.warning(f"TruffleHog finished with warnings: {result.stderr}")

        # Check if the output is empty
        if not result.stdout.strip():
            logging.info("TruffleHog completed successfully but found no secrets.")
            return

        try:
            output = json.loads(result.stdout)
            if not output:
                logging.info("TruffleHog completed successfully but found no secrets.")
                return
            with open(report_path, "w") as f:
                json.dump(output, f, indent=4)
        except json.JSONDecodeError as e:
            logging.error(f"TruffleHog produced invalid JSON output: {e}")
            with open(report_path, "w") as f:
                f.write(result.stdout)  # Save raw output for debugging
    except Exception as e:
        logging.exception("TruffleHog scan failed")
