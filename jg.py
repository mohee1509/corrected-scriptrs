import os
import subprocess
import logging
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# --- Load environment ---
load_dotenv()

BASE_DIR = Path(__file__).parent

# --- DAILY MATCHABLE LOG FILE ---
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

today = datetime.now().strftime("%Y-%m-%d")
log_file = LOG_DIR / f"SA_log_{today}.log"

logging.basicConfig(
    filename=str(log_file),
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger("daily_vendor_runner")

# ---------------------------------------------------------
# MATCHABLE ONE-LINE LOG WRITER  (THIS IS THE ONLY CHANGE)
# ---------------------------------------------------------
def write_matchable(vendor, script, status, error):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    error_clean = error.replace("\n", " ").replace("|", " ").strip() if error else "NONE"

    line = (
        f"{ts} | "
        f"VENDOR={vendor} | "
        f"SCRIPT={script} | "
        f"STATUS={status} | "
        f"ERROR=\"{error_clean}\""
    )
    logger.info(line)

# ---------------------------------------------------------
# EMAIL LOGIC (UNCHANGED)
# ---------------------------------------------------------
def send_email(subject, body):
    sender = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_PASSWORD")
    receiver = os.getenv("EMAIL_RECEIVER")

    if not sender or not password or not receiver:
        print("⚠️ Email variables missing — skipping email.")
        return

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
        print(f"📧 Email sent to {receiver}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# ---------------------------------------------------------
# SCRIPT COLLECTION (UNCHANGED)
# ---------------------------------------------------------
vendor_dirs = [
    d for d in os.listdir(BASE_DIR)
    if os.path.isdir(BASE_DIR / d)
    and d not in ["myenv", "__pycache__", "nvd"]
]

top_level_scripts = [
    f for f in os.listdir(BASE_DIR)
    if f.endswith(("_raw.py", "_normal.py"))
]

scripts_to_run = [BASE_DIR / f for f in top_level_scripts]

for vendor in vendor_dirs:
    vendor_path = BASE_DIR / vendor
    raw = sorted([vendor_path / f for f in os.listdir(vendor_path) if f.endswith("_raw.py")])
    normal = sorted([vendor_path / f for f in os.listdir(vendor_path) if f.endswith("_normal.py")])
    scripts_to_run.extend(raw + normal)

# ---------------------------------------------------------
# RUN UTILITY (UNCHANGED)
# ---------------------------------------------------------
def run_script(script_path):
    try:
        result = subprocess.run(
            ["/home/mohi/Desktop/DB/myenv/bin/python3", str(script_path)],
            capture_output=True, text=True, timeout=7200
        )
        output = (result.stdout + result.stderr).strip()
        return (True, output) if result.returncode == 0 else (False, output)
    except Exception as e:
        return False, str(e)

# ---------------------------------------------------------
# MAIN SCRIPT EXECUTION (UNCHANGED LOGIC)
# ---------------------------------------------------------
success_scripts = []
failed_scripts = []

for script_path in scripts_to_run:
    vendor = script_path.parent.name
    script_name = script_path.name

    print(f"▶ Running {script_name} ({vendor})...")

    success, err = run_script(script_path)

    if success:
        success_scripts.append(script_name)
        write_matchable(vendor, script_name, "SUCCESS", None)
    else:
        print("❌ Failed, retrying once...")

        success2, err2 = run_script(script_path)

        if success2:
            success_scripts.append(f"{script_name} (Retried)")
            write_matchable(vendor, script_name, "RETRY_SUCCESS", None)
        else:
            failed_scripts.append((script_name, err2))
            write_matchable(vendor, script_name, "FAILED", err2)

# ---------------------------------------------------------
# NVD RUNS (UNCHANGED)
# ---------------------------------------------------------
nvd_main = BASE_DIR / "nvd" / "run_nvd_enrichment.py"
if nvd_main.exists():
    success, err = run_script(nvd_main)
    write_matchable("NVD", nvd_main.name, "SUCCESS" if success else "FAILED", None if success else err)

nvd_other = BASE_DIR / "nvd" / "nvd_other_vendors.py"
if nvd_other.exists():
    success, err = run_script(nvd_other)
    write_matchable("NVD", nvd_other.name, "SUCCESS" if success else "FAILED", None if success else err)

# ---------------------------------------------------------
# EMAIL SUMMARY (UNCHANGED)
# ---------------------------------------------------------
summary = f"Daily Script Summary {today}\n"
summary += f"Success: {len(success_scripts)}\n"
summary += f"Failed: {len(failed_scripts)}\n"

send_email("Daily CVE Update Status", summary)

print(f"✔ Log saved: {log_file}")
