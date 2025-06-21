# Security Scan

A modular, Python-based security scanner for code repositories. Runs locally or as a scheduled GitHub Action. Designed for extensibility, security, and best practices.

## Features
- Runs open source security tools: Gitleaks, TruffleHog, Semgrep, Syft, Grype, Bandit, Safety
- Centralized scanning with easy future extension for repo-specific logic
- Structured logging with log rotation (14 days)
- JSON reports for each tool (in `reports/`)
- Configurable via YAML (`config/settings.yaml`)
- GitHub Actions workflow for scheduled or manual runs

## Project Structure
```text
security-scan/
├── main.py
├── scanners/
│   ├── gitleaks.py
│   ├── trufflehog.py
│   ├── semgrep.py
│   ├── syft.py
│   ├── grype.py
│   ├── bandit.py
│   ├── safety.py
├── reports/
├── logs/
├── config/
│   └── settings.yaml
├── requirements.txt
├── .gitignore
├── .github/
│   └── workflows/
│       └── security-scan.yml
└── README.md
```

## Usage

### Prerequisites

Ensure the following tools are installed and accessible in your system's PATH:

- **Dependency-Check**: Install using Homebrew on macOS:
  ```bash
  brew install dependency-check
  ```

- **Hadolint**: Install using Homebrew on macOS:
  ```bash
  brew install hadolint
  ```

- **Docker**: Ensure Docker is installed and running for Grype to analyze container images. You can download Docker from [Docker's official website](https://www.docker.com/).

### Local
1. Install Python 3.11+ and the required tools (see below).
2. Install Python dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
3. Install security tools (example for Ubuntu):
   ```bash
   sudo apt-get install gitleaks trufflehog semgrep syft grype bandit
   pip install safety
   ```
   For macOS, you can install the required tools using Homebrew:
   ```bash
   brew install gitleaks trufflehog semgrep syft grype bandit
   pip install safety
   ```
4. Edit `config/settings.yaml` as needed.
5. Run the scanner:
   ```bash
   python main.py
   ```
6. Reports will be in the `reports/` folder.

### GitHub Actions
- The workflow `.github/workflows/security-scan.yml` runs the scan on a schedule or manually.
- Reports are uploaded as workflow artifacts.

## Adding/Customizing Scanners
- Add new scanner modules in `scanners/` and import/call them in `main.py`.
- Adjust config and reporting as needed.

## Logging
- Logs are written to `logs/scan.log` and rotated daily (14 days kept).

## Reports
- Each tool outputs a JSON report in `reports/`.
- You can add HTML or summary report generation as needed.

## Security Best Practices
- Use a virtual environment.
- Keep secrets out of code/config.
- Restrict permissions on logs and reports if needed.

## Future Extensions
- Add repo-specific logic or scanning rules.
- Add more tools (e.g., CodeQL, Checkov, etc.) as needed.

---

### Note on Hadolint
`hadolint` is not a Python package and must be installed separately. For local installations, use Homebrew or download the binary directly. In CI/CD environments like GitHub Actions, it is installed as part of the workflow setup.

### Note on Safety
The `safety` tool is installed separately using `pip install safety` because it is designed to analyze the dependencies listed in `requirements.txt`. Including it in `requirements.txt` would create a circular dependency, as it would end up analyzing itself and other development tools, leading to unnecessary noise or false positives.

#### Configuring the Safety API Key
As of 2025, Safety requires an API key for authentication. Follow these steps to configure it:

1. Register for a free account at [Safety CLI Platform](https://platform.safetycli.com/).
2. Retrieve your API key from your account settings.
3. Set the API key as an environment variable:
   ```bash
   export SAFETY_API_KEY=your_api_key_here
   ```
4. Ensure the environment variable is available in your shell or CI/CD pipeline before running the scan.

If the API key is not provided, the scan will not proceed, and an error will be logged.

### Optimizing Dependency-Check for Multiple Repositories

To efficiently scan multiple repositories, follow these steps:

1. **Pre-Update the Database**:
   Run the following command once before scanning any repositories to ensure the database is up-to-date:
   ```bash
   dependency-check --update
   ```

2. **Reuse the Cached Database**:
   Dependency-Check automatically caches the downloaded data in its local data directory. Ensure this directory is not cleared between scans.

3. **Use an NVD API Key**:
   Register for an API key at [NVD API Key Registration](https://nvd.nist.gov/developers/request-an-api-key) and configure Dependency-Check to use it:
   ```bash
   dependency-check --nvdApiKey <your_api_key> --update
   ```

   It is free for Personal Use and usually you receive a few minutes after requesting it.

4. **Set Up a Local Mirror (Optional)**:
   For large-scale usage, consider setting up a local mirror of the NVD database. This eliminates the need to query the NVD servers entirely. Refer to the [Dependency-Check documentation](https://jeremylong.github.io/DependencyCheck/dependency-check-mirror.html) for instructions.

## Scanning Private Repositories

If you want to scan private repositories, you must provide a GitHub personal access token with access to those repositories. The recommended way is to use a fine-grained token.

### Creating a Fine-Grained GitHub Personal Access Token

1. Go to [GitHub Personal Access Tokens](https://github.com/settings/tokens).
2. Click **"Generate new token (fine-grained)"**.
3. Set a name (e.g., `security-scan script`) and expiration date.
4. Under **"Repository access"**, select the repositories you want to scan.
5. Under **"Repository permissions"**, set **Contents** to **Read-only** (or **Read and write** if you need to push changes).
6. Click **Generate token** and copy the token (you will not be able to see it again).
7. Add the token to your `.env` file in the project root:
   ```env
   GITHUB_TOKEN=your_copied_token
   ```

**Note:** Never share your token publicly. If it is ever exposed, revoke it immediately from your GitHub settings.

MIT License
