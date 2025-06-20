import logging
import subprocess

def run_subprocess(command, timeout=None):
    """Run a subprocess command with logging and error handling."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            logging.warning(f"Command finished with warnings: {result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(command)}")
    except Exception as e:
        logging.exception(f"Command failed: {' '.join(command)}")
    return None
