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

def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)

def generate_summary_report():
    logging.info("Generating summary report")
    reports = {}
    total_issues = 0

    # Filter out non-JSON files and empty files from summary report generation
    json_files = [f for f in os.listdir(REPORT_DIR) if os.path.isfile(os.path.join(REPORT_DIR, f)) and f.endswith('.json')]
    for json_file in json_files:
        try:
            file_path = os.path.join(REPORT_DIR, json_file)
            if os.path.getsize(file_path) == 0:
                logging.warning(f"Skipping empty JSON file {json_file}")
                continue

            with open(file_path, 'r') as f:
                content = json.load(f)
                if not content:
                    logging.warning(f"Skipping invalid or empty JSON file {json_file}")
                    continue
                reports[json_file] = content
                total_issues += len(content)
        except (json.JSONDecodeError, OSError) as e:
            logging.warning(f"Skipping invalid JSON file {json_file}: {e}")

    summary_template = Template("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Summary</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .high {
                color: red;
            }
            .medium {
                color: orange;
            }
            .low {
                color: green;
            }
        </style>
    </head>
    <body>
        <h1>Security Scan Summary</h1>
        <p><strong>Total Issues Found:</strong> {{ total_issues }}</p>
        <table>
            <tr>
                <th>Tool</th>
                <th>Issues Found</th>
                <th>Severity</th>
                <th>Details</th>
            </tr>
            {% for report, content in reports.items() %}
                <tr>
                    <td>{{ report }}</td>
                    <td>{{ content | length }}</td>
                    <td>
                        {% if content | length > 5 %}
                            <span class="high">High</span>
                        {% elif content | length > 2 %}
                            <span class="medium">Medium</span>
                        {% else %}
                            <span class="low">Low</span>
                        {% endif %}
                    </td>
                    <td><a href="{{ report }}" target="_blank">View Report</a></td>
                </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """)

    summary_html = summary_template.render(reports=reports, total_issues=total_issues)
    with open(os.path.join(REPORT_DIR, "summary.html"), "w") as f:
        f.write(summary_html)
    logging.info("Summary report generated at reports/summary.html")

def clone_repository(repo_path, branch, github_token):
    logging.info(f"Cloning repository: {repo_path} (branch: {branch})")
    local_path = os.path.join("cloned_repos", os.path.basename(repo_path))

    # Remove existing directory if it exists
    if os.path.exists(local_path):
        logging.warning(f"Removing existing directory: {local_path}")
        shutil.rmtree(local_path)

    try:
        if repo_path.startswith("http://") or repo_path.startswith("https://"):
            # Handle remote repository URL
            if github_token:
                repo_url = repo_path.replace("https://", f"https://{github_token}@")
            else:
                repo_url = repo_path

            subprocess.run([
                "git", "clone", "--branch", branch, repo_url, "--depth", "1", local_path
            ], check=True)
        else:
            # Handle local repository path
            if not os.path.exists(repo_path):
                raise FileNotFoundError(f"Local repository path does not exist: {repo_path}")

            subprocess.run([
                "git", "clone", "--branch", branch, repo_path, "--depth", "1", local_path
            ], check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logging.error(f"Failed to clone repository {repo_path}: {e}")

def is_valid_repository(repo_path):
    """Check if the repository path is valid."""
    if repo_path.startswith("http://") or repo_path.startswith("https://"):
        # Treat remote URLs as valid
        return True

    if not os.path.exists(repo_path):
        logging.error(f"Repository path does not exist: {repo_path}")
        return False
    try:
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        logging.error(f"Invalid Git repository: {repo_path}")
        return False

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

def main():
    config = load_config()
    # Update Dependency-Check database
    update_dependency_check_database()
    # Run all scanners
    for repo in config["repositories"]:
        if repo.get("skip", False):
            logging.info(f"Skipping repository: {repo['path']}")
            continue

        branch = repo.get("branch", config["general"]["branch"])
        local_path = os.path.join("cloned_repos", os.path.basename(repo["path"]))
        clone_repository(repo["path"], branch, GITHUB_TOKEN)
        logging.info(f"Scanning repository: {repo['path']} on branch {branch}")
        gitleaks.run_gitleaks(local_path, os.path.join(REPORT_DIR, f"gitleaks_{repo['path'].replace('/', '_')}.json"))
        trufflehog.run_trufflehog(local_path, os.path.join(REPORT_DIR, f"trufflehog_{repo['path'].replace('/', '_')}.json"))
        semgrep.run_semgrep(local_path, os.path.join(REPORT_DIR, f"semgrep_{repo['path'].replace('/', '_')}.json"))
        syft.run_syft(local_path, os.path.join(REPORT_DIR, f"syft_{repo['path'].replace('/', '_')}.json"))
        grype.run_grype(local_path, os.path.join(REPORT_DIR, f"grype_{repo['path'].replace('/', '_')}.json"))
        bandit.run_bandit(local_path, os.path.join(REPORT_DIR, f"bandit_{repo['path'].replace('/', '_')}.json"))
        safety.run_safety(config["general"]["requirements_path"], os.path.join(REPORT_DIR, f"safety_{repo['path'].replace('/', '_')}.json"))
        # Run additional scanners
        checkov.run_checkov(local_path, os.path.join(REPORT_DIR, f"checkov_{repo['path'].replace('/', '_')}.json"))
        dependency_check.run_dependency_check(local_path, os.path.join(REPORT_DIR, f"dependency-check_{repo['path'].replace('/', '_')}.json"))
        # Hadolint may fail if Dockerfile is not present, handle this case
        dockerfile_path = os.path.join(local_path, "Dockerfile")
        if os.path.exists(dockerfile_path):
            hadolint.run_hadolint(dockerfile_path, os.path.join(REPORT_DIR, f"hadolint_{repo['path'].replace('/', '_')}.json"))
        else:
            logging.warning(f"Dockerfile not found for repository {repo['path']}, skipping Hadolint")
    logging.info("All scans completed.")
    generate_summary_report()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Unhandled exception in main")
        sys.exit(1)
