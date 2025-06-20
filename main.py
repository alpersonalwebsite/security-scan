import json
import logging
import os
import sys
import yaml
from logging.handlers import TimedRotatingFileHandler
from jinja2 import Template
from dotenv import load_dotenv
from scanners import gitleaks, trufflehog, semgrep, syft, grype, bandit, safety, checkov, dependency_check, hadolint
import subprocess
import shutil
from modules.config_loader import load_config
from modules.repo_manager import clone_repository, is_valid_repository
from modules.report_generator import generate_summary_report

LOG_DIR = "logs"
REPORT_DIR = "reports"
CONFIG_PATH = "config/settings.yaml"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# Logging setup with rotation (14 days)
log_path = os.path.join(LOG_DIR, "scan.log")
logging.basicConfig(
    level=logging.DEBUG,
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

def get_report_path(repo_path, tool_name):
    """Generate a unique report path for each repository and tool."""
    repo_name = os.path.basename(repo_path.rstrip('/'))
    report_dir = os.path.join(REPORT_DIR, repo_name)
    os.makedirs(report_dir, exist_ok=True)
    return os.path.join(report_dir, f"{tool_name}.json")

def main():
    config = load_config(CONFIG_PATH)
    # Update Dependency-Check database
    update_dependency_check_database()
    # Run all scanners
    for repo in config["repositories"]:
        if repo.get("skip", False):
            logging.info(f"Skipping repository: {repo['path']}")
            continue

        branch = repo.get("branch", config["general"]["branch"])
        local_path = clone_repository(repo["path"], branch, GITHUB_TOKEN)
        logging.info(f"Scanning repository: {repo['path']} on branch {branch}")
        gitleaks.run_gitleaks(local_path, get_report_path(repo["path"], "gitleaks"))
        trufflehog.run_trufflehog(local_path, get_report_path(repo["path"], "trufflehog"))
        semgrep.run_semgrep(local_path, get_report_path(repo["path"], "semgrep"))
        syft.run_syft(local_path, get_report_path(repo["path"], "syft"))
        grype.run_grype(local_path, get_report_path(repo["path"], "grype"))
        bandit.run_bandit(local_path, get_report_path(repo["path"], "bandit"))
        safety.run_safety(config["general"]["requirements_path"], get_report_path(repo["path"], "safety"))
        checkov.run_checkov(local_path, get_report_path(repo["path"], "checkov"))
        dependency_check.run_dependency_check(local_path, get_report_path(repo["path"], "dependency-check"))
        dockerfile_path = os.path.join(local_path, "Dockerfile")
        if os.path.exists(dockerfile_path):
            hadolint.run_hadolint(dockerfile_path, get_report_path(repo["path"], "hadolint"))
        else:
            logging.warning(f"Dockerfile not found for repository {repo['path']}, skipping Hadolint")
        # Update the summary report generation to place it inside the repository-specific folder
        repo_name = os.path.basename(repo["path"].rstrip('/'))
        generate_summary_report(os.path.join(REPORT_DIR, repo_name), os.path.join(REPORT_DIR, repo_name, "summary.html"))
    logging.info("All scans completed.")
    # Removed the generation of the summary.html in the root reports folder

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Unhandled exception in main")
        sys.exit(1)
