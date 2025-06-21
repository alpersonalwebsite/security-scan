import json
import logging
import os
import sys
import yaml
from logging.handlers import TimedRotatingFileHandler
import subprocess
import shutil

from jinja2 import Template

from dotenv import load_dotenv

from scanners import gitleaks, trufflehog, semgrep, syft, grype, bandit, safety, checkov, dependency_check, hadolint
import socket
from azure.core.pipeline.policies import HeadersPolicy, UserAgentPolicy
from azure.core.pipeline import Pipeline
from azure.core.pipeline.transport import RequestsTransport
import argparse
from modules.config_loader import load_config
from modules.repo_manager import clone_repository, is_valid_repository
from modules.report_generator import generate_summary_report
from datetime import datetime
from modules.json_to_html import render_html_from_json, render_html_from_json_recursive

LOG_DIR = "logs"
REPORT_DIR = "reports"
CONFIG_PATH = "config/settings.yaml"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# Logging setup with rotation (14 days)
log_path = os.path.join(LOG_DIR, "scan.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        TimedRotatingFileHandler(log_path, when="D", interval=1, backupCount=14),
        logging.StreamHandler(sys.stdout)
    ]
)

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

def update_dependency_check_database():
    logging.info("Updating OWASP Dependency-Check database")
    try:
        result = subprocess.run([
            "dependency-check", "--update"
        ], capture_output=True, text=True, timeout=600)  # Timeout set to 10 minutes
        if result.returncode != 0:
            logging.warning(f"Dependency-Check update finished with warnings: {result.stderr}")
    except subprocess.TimeoutExpired:
        logging.error("Dependency-Check update timed out")
    except Exception as e:
        logging.exception("Dependency-Check update failed")

# Ensure cloned_repos directory exists
os.makedirs("cloned_repos", exist_ok=True)

def get_timestamped_report_path(repo_path):
    """Generate a timestamped report path for each repository, with json and html subfolders."""
    repo_name = os.path.basename(repo_path.rstrip('/'))
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_dir = os.path.join(REPORT_DIR, repo_name, timestamp)
    json_dir = os.path.join(report_dir, "json")
    html_dir = os.path.join(report_dir, "html")
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    return report_dir

def get_report_path(repo_path, tool_name, timestamped_dir, fmt="json"):
    """Generate a unique report path for each repository and tool, in the correct subfolder."""
    if fmt == "json":
        return os.path.join(timestamped_dir, "json", f"{tool_name}.json")
    elif fmt == "html":
        return os.path.join(timestamped_dir, "html", f"{tool_name}.html")
    else:
        raise ValueError("Unsupported report format")

def is_azurite_running(host='127.0.0.1', port=10000, timeout=1):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False

def upload_reports_to_azurite(report_dir, repo_name, blob_port=10000, connection_string=None):
    sanitized_repo_name = repo_name.lower().replace('_', '-').replace('.', '-')
    if not is_azurite_running(port=blob_port):
        logging.warning(f"Azurite is not running on 127.0.0.1:{blob_port}. Skipping upload for this repository.")
        return
    if not connection_string:
        endpoint = f"http://127.0.0.1:{blob_port}/devstoreaccount1"
        connection_string = get_connection_string(
            os.getenv("STORAGE_ACCOUNT_NAME", "devstoreaccount1"),
            os.getenv("STORAGE_ACCOUNT_KEY", "Eby8vdM02xNOcqFeqCnf2P=="),
            endpoint
        )
    from azure.storage.blob import BlobServiceClient
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client(sanitized_repo_name)
    try:
        if not container_client.exists():
            container_client.create_container()
        # Only show minimal info in INFO mode
        if logging.getLogger().getEffectiveLevel() == logging.INFO:
            logging.info(f"Container '{sanitized_repo_name}' exists or was created successfully.")
    except Exception as e:
        logging.error(f"Error during container creation or existence check: {e}")
        return
    # Upload the entire report_dir (date-time folder) recursively, preserving structure
    for root, dirs, files in os.walk(report_dir):
        for file in files:
            abs_path = os.path.join(root, file)
            rel_path = os.path.relpath(abs_path, report_dir)
            blob_path = f"{os.path.basename(report_dir)}/{rel_path}"
            try:
                with open(abs_path, 'rb') as data:
                    container_client.upload_blob(blob_path, data, overwrite=True)
                # Only show minimal info in INFO mode
                if logging.getLogger().getEffectiveLevel() == logging.INFO:
                    logging.info(f"Uploaded {blob_path} to Azurite container '{sanitized_repo_name}'")
            except Exception as e:
                logging.error(f"Error uploading {blob_path}: {e}")

def get_connection_string(account_name, account_key, endpoint):
    """
    Generate a connection string for Azure Blob Storage or Azurite.
    :param account_name: The storage account name.
    :param account_key: The storage account key.
    :param endpoint: The storage account endpoint.
    :return: A formatted connection string.
    """
    return f"DefaultEndpointsProtocol=http;AccountName={account_name};AccountKey={account_key};BlobEndpoint={endpoint};"

# Load environment variables for Azurite connection
account_name = os.getenv("STORAGE_ACCOUNT_NAME", "devstoreaccount1")
account_key = os.getenv("STORAGE_ACCOUNT_KEY", "Eby8vdM02xNOcqFeqCnf2P==")
account_endpoint = os.getenv("STORAGE_ACCOUNT_ENDPOINT", "http://127.0.0.1:10000/devstoreaccount1")

azurite_connection_string = get_connection_string(account_name, account_key, account_endpoint)

# Configure Azure SDK logging: only show HTTP request/response logs in DEBUG mode
azure_loggers = [
    "azure.core.pipeline.policies.http_logging_policy",
    "azure.storage.blob",
    "azure.core.pipeline",
    "azure.core.pipeline.transport",
    "azure.core.pipeline.policies",
    "azure.core.pipeline.policies._universal",
    "azure.core.pipeline.policies._authentication",
    "azure.core.pipeline.policies._retry",
    "azure.core.pipeline.policies._redirect",
    "azure.core.pipeline.policies._logging",
    "azure.core.pipeline.policies._distributed_tracing",
    "azure.core.pipeline.policies._custom_hook",
    "azure.core.pipeline.policies._http_logging_policy",
    "azure"
]
for logger_name in azure_loggers:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG if logging.getLogger().getEffectiveLevel() == logging.DEBUG else logging.WARNING)

# Improved argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="Security scan runner")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-dev", action="store_true", help="Run in development mode (default)")
    group.add_argument("-prod", "--production", action="store_true", help="Run in production mode")
    parser.add_argument("--config", type=str, default=CONFIG_PATH, help="Path to config YAML file")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--blobPort", type=int, default=None, help="Azurite Blob service port (dev only, default: 10000)")
    args = parser.parse_args()
    # Enforce --blobPort is only allowed in dev mode
    if args.production and args.blobPort is not None:
        parser.error("--blobPort is only allowed in development mode. Do not use it with -prod or --production.")
    return args

def main():
    args = parse_arguments()
    config = load_config(args.config)
    # Only override log level if not default (INFO)
    if args.log_level.upper() != "INFO":
        logging.getLogger().setLevel(args.log_level.upper())
    blob_port = args.blobPort if (args.blobPort is not None and not getattr(args, 'production', False)) else 10000
    account_name = os.getenv("STORAGE_ACCOUNT_NAME", "devstoreaccount1")
    account_key = os.getenv("STORAGE_ACCOUNT_KEY", "Eby8vdM02xNOcqFeqCnf2P==")
    env_endpoint = os.getenv("STORAGE_ACCOUNT_ENDPOINT", None)
    if env_endpoint:
        import re
        endpoint = re.sub(r":\\d+", f":{blob_port}", env_endpoint)
    else:
        endpoint = f"http://127.0.0.1:{blob_port}/devstoreaccount1"
    azurite_connection_string = get_connection_string(account_name, account_key, endpoint)
    update_dependency_check_database()
    for repo in config["repositories"]:
        if repo.get("skip", False):
            logging.info(f"Skipping repository: {repo['path']}")
            continue
        branch = repo.get("branch", config["general"]["branch"])
        local_path = clone_repository(repo["path"], branch, GITHUB_TOKEN)
        logging.info(f"Scanning repository: {repo['path']} on branch {branch}")
        timestamped_dir = get_timestamped_report_path(repo["path"])
        # List of (tool, run_function) pairs
        tools = [
            ("gitleaks", gitleaks.run_gitleaks),
            ("trufflehog", trufflehog.run_trufflehog),
            ("semgrep", semgrep.run_semgrep),
            ("syft", syft.run_syft),
            ("grype", grype.run_grype),
            ("bandit", bandit.run_bandit),
            ("safety", lambda path, out: safety.run_safety(config["general"]["requirements_path"], out)),
            ("checkov", checkov.run_checkov),
            ("dependency-check", dependency_check.run_dependency_check),
        ]
        for tool_name, run_func in tools:
            json_path = get_report_path(repo["path"], tool_name, timestamped_dir, fmt="json")
            run_func(local_path, json_path)
            html_path = get_report_path(repo["path"], tool_name, timestamped_dir, fmt="html")
            try:
                # Special handling for Checkov: if output is a directory, process recursively
                if tool_name == "checkov" and os.path.isdir(json_path):
                    # Recursively process all JSON files in the directory
                    checkov_html_dir = os.path.join(timestamped_dir, "html", "checkov")
                    os.makedirs(checkov_html_dir, exist_ok=True)
                    render_html_from_json_recursive(json_path, checkov_html_dir, report_title="Checkov Report", scanner_name="checkov")
                else:
                    render_html_from_json(json_path, html_path, report_title=f"{tool_name.capitalize()} Report", scanner_name=tool_name)
            except Exception as e:
                logging.warning(f"Failed to generate HTML for {tool_name}: {e}")
        dockerfile_path = os.path.join(local_path, "Dockerfile")
        if os.path.exists(dockerfile_path):
            hadolint_json = get_report_path(repo["path"], "hadolint", timestamped_dir, fmt="json")
            hadolint.run_hadolint(dockerfile_path, hadolint_json)
            hadolint_html = get_report_path(repo["path"], "hadolint", timestamped_dir, fmt="html")
            try:
                render_html_from_json(hadolint_json, hadolint_html, report_title="Hadolint Report", scanner_name="hadolint")
            except Exception as e:
                logging.warning(f"Failed to generate HTML for hadolint: {e}")
        else:
            logging.warning(f"Dockerfile not found for repository {repo['path']}, skipping Hadolint")
        repo_name = os.path.basename(repo["path"].rstrip('/'))
        generate_summary_report(timestamped_dir, os.path.join(timestamped_dir, "summary.html"))
        if not getattr(args, 'production', False):
            upload_reports_to_azurite(timestamped_dir, repo_name, blob_port=blob_port, connection_string=azurite_connection_string)
        else:
            logging.info("Production mode: skipping Azurite upload.")
    logging.info("All scans completed.")
    # Removed the generation of the summary.html in the root reports folder

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print("[EXCEPTION] Unhandled exception in main:")
        print(traceback.format_exc())
        logging.exception("Unhandled exception in main")
        sys.exit(1)
