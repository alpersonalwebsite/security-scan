import os
import json
import logging
from jinja2 import Template

def generate_summary_report(report_dir, output_path):
    """Generate an HTML summary report from JSON files in the json/ subfolder, linking to HTML reports."""
    logging.info("Generating summary report")
    reports = {}
    total_issues = 0

    json_dir = os.path.join(report_dir, "json")
    html_dir = os.path.join(report_dir, "html")
    # --- Check for checkov as a directory ---
    checkov_json_dir = os.path.join(json_dir, "checkov.json")
    checkov_html_dir = os.path.join(html_dir, "checkov")
    if os.path.isdir(checkov_json_dir):
        checkov_issue_count = 0
        checkov_html_link = None
        for root, dirs, files in os.walk(checkov_json_dir):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = json.load(f)
                        # Count failed checks if present, else total items
                        if isinstance(content, list):
                            for entry in content:
                                if isinstance(entry, dict) and 'results' in entry and 'failed_checks' in entry['results']:
                                    checkov_issue_count += len(entry['results']['failed_checks'])
                        elif isinstance(content, dict) and 'results' in content and 'failed_checks' in content['results']:
                            checkov_issue_count += len(content['results']['failed_checks'])
                        elif isinstance(content, dict) and 'failed_checks' in content:
                            checkov_issue_count += len(content['failed_checks'])
                        else:
                            checkov_issue_count += 0
                        # Find the first HTML file for linking
                        rel_path = os.path.relpath(file_path, checkov_json_dir)
                        html_candidate = os.path.join(checkov_html_dir, os.path.splitext(rel_path)[0] + '.html')
                        if not checkov_html_link and os.path.isfile(html_candidate):
                            checkov_html_link = os.path.relpath(html_candidate, report_dir)
                    except Exception as e:
                        logging.warning(f"Skipping invalid Checkov JSON file {file_path}: {e}")
        reports['checkov'] = {
            'count': checkov_issue_count,
            'html': checkov_html_link
        }
        total_issues += checkov_issue_count
    # --- End Checkov directory logic ---

    # Look for JSON files in the json/ subfolder (excluding checkov.json dir)
    if not os.path.isdir(json_dir):
        logging.warning(f"No json/ subfolder found in {report_dir}")
        json_files = []
    else:
        json_files = [f for f in os.listdir(json_dir) if os.path.isfile(os.path.join(json_dir, f)) and f.endswith('.json')]
    for json_file in json_files:
        if json_file == "checkov.json":
            continue  # skip directory, already handled
        try:
            file_path = os.path.join(json_dir, json_file)
            if os.path.getsize(file_path) == 0:
                logging.warning(f"Skipping empty JSON file {json_file}")
                continue
            with open(file_path, 'r') as f:
                content = json.load(f)
                if isinstance(content, list):
                    issue_count = len(content)
                elif isinstance(content, dict):
                    if 'results' in content:
                        issue_count = len(content['results'])
                    elif 'matches' in content:
                        issue_count = len(content['matches'])
                    elif 'dependencies' in content:
                        issue_count = sum(1 for d in content['dependencies'] if d.get('vulnerabilities'))
                    else:
                        issue_count = 0
                else:
                    issue_count = 0
                tool_name = os.path.splitext(json_file)[0]
                html_file = f"{tool_name}.html"
                html_exists = os.path.isfile(os.path.join(html_dir, html_file))
                reports[tool_name] = {
                    'count': issue_count,
                    'html': f"html/{html_file}" if html_exists else None
                }
                total_issues += issue_count
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
            {% for tool, info in reports.items() %}
                <tr>
                    <td>{{ tool }}</td>
                    <td>{{ info.count }}</td>
                    <td>
                        {% if info.count > 5 %}
                            <span class="high">High</span>
                        {% elif info.count > 2 %}
                            <span class="medium">Medium</span>
                        {% else %}
                            <span class="low">Low</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if info.html %}
                            <a href="{{ info.html }}" target="_blank">View Report</a>
                        {% else %}
                            <span style="color: #888;">No HTML</span>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """)

    summary_html = summary_template.render(reports=reports, total_issues=total_issues)
    with open(output_path, "w") as f:
        f.write(summary_html)
    logging.info(f"Summary report generated at {output_path}")
