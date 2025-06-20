import json
import logging
import os
import re
import subprocess

API_KEY_ENV_VAR = "SAFETY_API_KEY"

def extract_json_from_output(output):
    """Extract JSON data from Safety CLI output."""
    # Look for the JSON block in the output
    json_start = output.find("{")
    json_end = output.rfind("}")
    if json_start != -1 and json_end != -1:
        try:
            return output[json_start:json_end + 1]
        except Exception as e:
            logging.error(f"Error extracting JSON: {e}")
    return None

def parse_safety_output(output):
    """Parse structured text output from Safety and convert it into JSON."""
    parsed_data = {
        "dependencies": [],
        "summary": {}
    }

    lines = output.splitlines()
    current_dependency = None

    for line in lines:
        if line.startswith("📝"):
            if current_dependency:
                parsed_data["dependencies"].append(current_dependency)
            current_dependency = {
                "name": line.split()[1],
                "vulnerabilities": []
            }
        elif line.startswith("  -> Vuln ID") and current_dependency:
            vuln_id = line.split(":")[1].strip()
            current_dependency["vulnerabilities"].append({"id": vuln_id})
        elif line.startswith("Update") and current_dependency:
            current_dependency["fix"] = line.strip()
        elif line.startswith("Tested"):
            parsed_data["summary"] = line.strip()

    if current_dependency:
        parsed_data["dependencies"].append(current_dependency)

    return parsed_data

def run_safety(requirements_path, report_path):
    api_key = os.getenv(API_KEY_ENV_VAR)
    if not api_key:
        logging.error(f"API key not found. Please set the {API_KEY_ENV_VAR} environment variable.")
        return

    logging.info(f"Running Safety on {requirements_path} with API key")
    try:
        result = subprocess.run([
            "safety", "scan", "--file", requirements_path, "--json", "--key", api_key
        ], capture_output=True, text=True)
        # Log raw output for debugging
        logging.debug(f"Raw Safety output: {result.stdout}")

        # Save raw output to a file for analysis
        raw_output_path = report_path.replace(".json", "_raw_output.txt")
        with open(raw_output_path, "w") as raw_file:
            raw_file.write(result.stdout)

        if result.returncode != 0:
            logging.warning(f"Safety finished with warnings: {result.stderr}")

        # Parse the structured text output
        parsed_data = parse_safety_output(result.stdout)
        with open(report_path, "w") as f:
            json.dump(parsed_data, f, indent=4)

    except Exception as e:
        logging.exception("Safety scan failed")
