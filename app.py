import os
import subprocess
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from flask import Flask, request, render_template, send_file
import threading
import shutil

app = Flask(__name__)

# Configuration
TARGET_DOMAIN = ""
OUTPUT_DIR = "bug_bounty_output"
REPORT_PDF = os.path.join(OUTPUT_DIR, "bug_bounty_report.pdf")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
SUBFINDER_CONFIG = "/root/.config/subfinder/config.yaml"  # Path to config.yaml in Docker

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_command(command, output_file=None):
    """Execute a shell command and optionally save output to a file."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout + result.stderr)
        return result.stdout + result.stderr
    except Exception as e:
        print(f"Error running command {command}: {e}")
        return str(e)

def generate_pdf_report(findings):
    """Generate a PDF report with findings and screenshots."""
    doc = SimpleDocTemplate(REPORT_PDF, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"Bug Bounty Report for {TARGET_DOMAIN}", styles['Title']))
    story.append(Spacer(1, 12))

    for section, data in findings.items():
        story.append(Paragraph(section, styles['Heading1']))
        story.append(Paragraph(data['text'], styles['BodyText']))
        if 'screenshots' in data:
            for img in data['screenshots']:
                if os.path.exists(img):
                    try:
                        story.append(Image(img, width=400, height=300))
                    except Exception as e:
                        story.append(Paragraph(f"Error loading image {img}: {e}", styles['BodyText']))
        story.append(Spacer(1, 12))

    doc.build(story)
    print(f"PDF report generated: {REPORT_PDF}")

def recon_workflow(target):
    """Execute the bug bounty reconnaissance workflow."""
    global TARGET_DOMAIN
    TARGET_DOMAIN = target
    findings = {}

    # 1. Subdomain Enumeration
    print("Enumerating subdomains...")
    subfinder_out = os.path.join(OUTPUT_DIR, f"subfinder_{TIMESTAMP}.txt")
    assetfinder_out = os.path.join(OUTPUT_DIR, f"assetfinder_{TIMESTAMP}.txt")
    subdomains_out = os.path.join(OUTPUT_DIR, f"subdomains_{TIMESTAMP}.txt")

    run_command(f"subfinder -d {target} -o {subfinder_out} -config {SUBFINDER_CONFIG}")
    run_command(f"assetfinder {target} > {assetfinder_out}")

    # Combine and deduplicate subdomains
    subdomains = set()
    for file in [subfinder_out, assetfinder_out]:
        if os.path.exists(file):
            with open(file, 'r') as f:
                subdomains.update(line.strip() for line in f if line.strip())
    
    with open(subdomains_out, 'w') as out:
        out.write('\n'.join(subdomains))
    
    findings['Subdomain Enumeration'] = {'text': f"Found {len(subdomains)} unique subdomains. Output saved to {subdomains_out}"}

    # 2. Filter Live Domains
    print("Filtering live domains...")
    live_subdomains_out = os.path.join(OUTPUT_DIR, f"live_subdomains_{TIMESTAMP}.txt")
    run_command(f"cat {subdomains_out} | httpx -silent > {live_subdomains_out}")
    
    live_count = 0
    if os.path.exists(live_subdomains_out):
        with open(live_subdomains_out, 'r') as f:
            live_count = len([line for line in f if line.strip()])
    findings['Live Domains'] = {'text': f"Identified {live_count} live subdomains. Output saved to {live_subdomains_out}"}

    # 3. Subdomain Takeover Check
    print("Checking for subdomain takeovers...")
    subzy_out = os.path.join(OUTPUT_DIR, f"subzy_{TIMESTAMP}.txt")
    subjack_out = os.path.join(OUTPUT_DIR, f"subjack_{TIMESTAMP}.txt")
    
    run_command(f"subzy run --targets {subdomains_out} > {subzy_out}")
    run_command(f"subjack -w {subdomains_out} -t 100 -o {subjack_out} -ssl")
    
    takeover_findings = []
    for out_file in [subzy_out, subjack_out]:
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                takeover_findings.append(f.read())
    findings['Subdomain Takeover'] = {'text': f"Takeover check results:\n{''.join(takeover_findings)}"}

    # 4. Parse JavaScript Files
    print("Parsing JavaScript files...")
    katana_out = os.path.join(OUTPUT_DIR, f"katana_{TIMESTAMP}.txt")
    run_command(f"katana -u {live_subdomains_out} -o {katana_out}")
    
    findings['JavaScript Parsing'] = {'text': f"JavaScript endpoints saved to {katana_out}"}

    # 5. Secret Finder
    print("Searching for secrets...")
    secret_out = os.path.join(OUTPUT_DIR, f"secrets_{TIMESTAMP}.txt")
    run_command(f"python3 SecretFinder/SecretFinder.py -i {live_subdomains_out} -o cli > {secret_out}")
    
    secrets = "No secrets found."
    if os.path.exists(secret_out):
        with open(secret_out, 'r') as f:
            secrets = f.read() or secrets
    findings['Secret Finder'] = {'text': f"Secrets found:\n{secrets}"}

    # 6. Capture Screenshots
    print("Capturing screenshots...")
    eyewitness_out = os.path.join(OUTPUT_DIR, f"eyewitness_{TIMESTAMP}")
    run_command(f"python3 EyeWitness/Python/EyeWitness.py -f {live_subdomains_out} --web -d {eyewitness_out}")
    
    screenshots = []
    if os.path.exists(eyewitness_out):
        screenshots = [os.path.join(eyewitness_out, f) for f in os.listdir(eyewitness_out) if f.endswith('.png')]
    findings['Screenshots'] = {'text': f"Captured {len(screenshots)} screenshots.", 'screenshots': screenshots}

    # 7. Additional Vulnerability Scanning
    print("Running additional scans...")
    nuclei_out = os.path.join(OUTPUT_DIR, f"nuclei_{TIMESTAMP}.txt")
    dirsearch_out = os.path.join(OUTPUT_DIR, f"dirsearch_{TIMESTAMP}.txt")
    ffuf_out = os.path.join(OUTPUT_DIR, f"ffuf_{TIMESTAMP}.txt")
    sqlmap_out = os.path.join(OUTPUT_DIR, f"sqlmap_{TIMESTAMP}.txt")
    
    run_command(f"nuclei -l {live_subdomains_out} -o {nuclei_out}")
    run_command(f"python3 dirsearch/dirsearch.py -l {live_subdomains_out} -e * -o {dirsearch_out}")
    run_command(f"ffuf -w wordlist.txt -u 'https://FUZZ' -H 'User-Agent: Mozilla/5.0' -o {ffuf_out} -i {live_subdomains_out}")
    run_command(f"python3 sqlmap/sqlmap.py -m {live_subdomains_out} --batch -o {sqlmap_out}")
    
    vuln_findings = []
    for out_file in [nuclei_out, dirsearch_out, ffuf_out, sqlmap_out]:
        if os.path.exists(out_file):
            with open(out_file, 'r') as f:
                content = f.read()
                if content.strip():
                    vuln_findings.append(content)
    findings['Vulnerability Scans'] = {'text': f"Vulnerability scan results:\n{''.join(vuln_findings)}"}

    # Generate PDF Report
    generate_pdf_report(findings)
    return findings

@app.route('/', methods=['GET', 'POST'])
def index():
    """Flask web interface for hosting on Render."""
    if request.method == 'POST':
        target = request.form['domain']
        threading.Thread(target=recon_workflow, args=(target,)).start()
        return render_template('index.html', message=f"Recon started for {target}. Check {OUTPUT_DIR} for results or download the report.")
    return render_template('index.html')

@app.route('/download')
def download_report():
    """Download the generated PDF report."""
    if os.path.exists(REPORT_PDF):
        return send_file(REPORT_PDF, as_attachment=True)
    return "Report not found.", 404

if __name__ == '__main__':
    # Local execution
    target = input("Enter target domain: ")
    recon_workflow(target)
    # Uncomment to run Flask locally
    # app.run(debug=True)
