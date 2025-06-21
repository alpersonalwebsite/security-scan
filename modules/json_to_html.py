import os
import json
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
import logging
import fnmatch
import datetime

def render_html_from_json(json_path, html_path, report_title="Security Report", scanner_name=None):
    try:
        # Skip if the path is a directory
        if os.path.isdir(json_path):
            print(f"[WARNING] Skipping directory: {json_path}")
            return
        # Load JSON data
        with open(json_path) as f:
            data = json.load(f)
        # Inject tool_name if missing and scanner_name is provided
        if isinstance(data, dict) and scanner_name and 'tool_name' not in data:
            data['tool_name'] = scanner_name.capitalize()
        # Flatten data for table rendering (assume list of dicts or dict with 'results' key)
        if isinstance(data, dict) and 'results' in data:
            items = data['results']
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print(f"[DEBUG] items for rendering: {items}")
        # Determine columns
        columns = set()
        for item in items:
            if isinstance(item, dict):
                columns.update(item.keys())
        columns = sorted(columns)
        # Prepare Jinja2 environment
        env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '../templates')))
        # Determine template name
        template_name = 'report_template.html'
        if scanner_name:
            specific_template = f'{scanner_name}_template.html'
            try:
                template = env.get_template(specific_template)
                template_name = specific_template
            except TemplateNotFound:
                template = env.get_template(template_name)
        else:
            template = env.get_template(template_name)
        # Render HTML
        year = datetime.datetime.now().year
        html = template.render(report_title=report_title, items=items, columns=columns, data=data, year=year)
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            print(f"[DEBUG] Rendered HTML preview:\n{html[:500]}")
            print(f"[DEBUG] Writing HTML to: {html_path}")
        # Write HTML to file
        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[INFO] HTML report generated using {template_name}: {html_path}")
    except Exception as e:
        print(f"[ERROR] Exception during HTML generation: {e}")
        import traceback
        print(traceback.format_exc())

def render_html_from_json_recursive(input_path, output_dir, report_title="Security Report", scanner_name=None):
    """
    Recursively process all JSON files in a directory (or a single file), generating HTML reports for each.
    For Checkov, use the checkov template.
    """
    if os.path.isfile(input_path) and input_path.endswith('.json'):
        # Single file
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        html_path = os.path.join(output_dir, f"{base_name}.html")
        render_html_from_json(input_path, html_path, report_title, scanner_name)
        return
    for root, dirs, files in os.walk(input_path):
        for filename in fnmatch.filter(files, '*.json'):
            json_path = os.path.join(root, filename)
            # Determine scanner_name by file or directory name
            # Special case: if "checkov" in path, use checkov template
            if 'checkov' in json_path.lower():
                scanner = 'checkov'
            else:
                scanner = scanner_name
            # Output HTML path mirrors the input structure under output_dir
            rel_path = os.path.relpath(json_path, input_path)
            html_path = os.path.join(output_dir, os.path.splitext(rel_path)[0] + '.html')
            os.makedirs(os.path.dirname(html_path), exist_ok=True)
            render_html_from_json(json_path, html_path, report_title, scanner)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python json_to_html.py <input.json|input_dir> <output.html|output_dir> [Report Title] [Scanner Name]")
        exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    report_title = sys.argv[3] if len(sys.argv) > 3 else "Security Report"
    scanner_name = sys.argv[4] if len(sys.argv) > 4 else None
    if os.path.isdir(input_path):
        render_html_from_json_recursive(input_path, output_path, report_title, scanner_name)
    else:
        render_html_from_json(input_path, output_path, report_title, scanner_name)
