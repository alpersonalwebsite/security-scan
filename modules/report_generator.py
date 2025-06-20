import os
import json
import logging
from jinja2 import Template

def generate_summary_report(report_dir, output_path):
    """Generate an HTML summary report from JSON files."""
    logging.info("Generating summary report")
    reports = {}
    total_issues = 0

    # Filter out non-JSON files and empty files from summary report generation
    json_files = [f for f in os.listdir(report_dir) if os.path.isfile(os.path.join(report_dir, f)) and f.endswith('.json')]
    for json_file in json_files:
        try:
            file_path = os.path.join(report_dir, json_file)
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
    with open(output_path, "w") as f:
        f.write(summary_html)
    logging.info(f"Summary report generated at {output_path}")
