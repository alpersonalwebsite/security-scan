import os
import shutil
import subprocess
import logging

def clone_repository(repo_path, branch, github_token, local_base_path="cloned_repos"):
    """Clone a repository to a local path."""
    logging.info(f"Cloning repository: {repo_path} (branch: {branch})")
    local_path = os.path.join(local_base_path, os.path.basename(repo_path))

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

    return local_path

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
