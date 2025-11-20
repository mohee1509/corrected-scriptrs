# checkpoint_raw_playwright_stealth.py
import os, json, logging, time, random, requests, psycopg2
from psycopg2.extras import Json
from datetime import datetime
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from tqdm import tqdm
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# --- Setup & Config ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("checkpoint_raw")

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS"),
}

VENDOR_NAME = "Check_point"
API_URL = "https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive"
ADVISORY_SOURCE_BASE_URL = "https://support.checkpoint.com/security-advisories/"
ADVISORY_SCRAPE_BASE_URL = "https://support.checkpoint.com/results/sk/"

REQUEST_TIMEOUT = 60
NAV_RETRIES = 3

# --- DB helpers ---
def init_db(): return psycopg2.connect(**DB_CONFIG)

def get_existing_urls(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT source_url FROM vendor_staging_table WHERE vendor_name = %s;", (VENDOR_NAME,))
        return {r[0] for r in cur.fetchall()}

def insert_advisory(conn, src, data):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO vendor_staging_table (vendor_name, source_url, raw_data, processed)
                       VALUES (%s,%s,%s,%s)
                       ON CONFLICT (source_url) DO NOTHING;""",
                       (VENDOR_NAME, src, Json(data), False))
    conn.commit()

# --- utils ---

def convert_timestamp(ms): return None if not ms else datetime.fromtimestamp(ms/1000).strftime("%Y-%m-%d %H:%M:%S")

def extract_text(html): return BeautifulSoup(html, "html.parser").get_text(" ", strip=True)

def extract_solution(html):
    try:
        soup = BeautifulSoup(html, "html.parser")
        parts = []
        for tag in soup.find_all(["p","li","strong","span","table"]):
            txt = tag.get_text(" ", strip=True)
            if txt: parts.append(txt)
        return ", ".join(parts)
    except: return None

def parse_html(html, url):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.select_one("#sk_content h1")
    symptoms = soup.select_one("#symptoms")
    solution = soup.select_one("#solution")
    return {
        "solution_title": title.get_text(strip=True) if title else None,
        "Symptoms": extract_text(str(symptoms)) if symptoms else None,
        "Solution": extract_solution(str(solution)) if solution else None,
        "advisory_url": url
    }

# --- Playwright anti-bot setup ---
def fetch_page_and_parse(page, url):
    for attempt in range(1, NAV_RETRIES+1):
        try:
            page.goto(url, timeout=REQUEST_TIMEOUT*1000)
            page.wait_for_selector("body", timeout=REQUEST_TIMEOUT*1000)
            time.sleep(random.uniform(1.5, 2.5))
            html = page.content()
            if "client-side exception" in html or "Application error" in html:
                logger.warning(f"⚠️ Client-side error on {url}")
                continue
            data = parse_html(html, url)
            if data.get("Solution") or data.get("Symptoms"):
                return data
        except PlaywrightTimeoutError:
            logger.warning(f"⏱ Timeout {url} (attempt {attempt})")
        except Exception as e:
            logger.warning(f"⚠️ Error {url} (attempt {attempt}): {e}")
        time.sleep(random.uniform(2, 4))
    return {}

# --- Main ---
def main():
    logger.info("🚀 Starting Check Point Stealth Scraper")

    resp = requests.get(API_URL, timeout=30)
    resp.raise_for_status()
    advisories = resp.json()
    logger.info(f"Fetched {len(advisories)} advisories from API")

    conn = init_db()
    existing = get_existing_urls(conn)
    inserted = 0

    with sync_playwright() as p:
        # Launch full Chrome instead of Playwright Chromium
        chrome_path = p.chromium.executable_path
        browser = p.chromium.launch_persistent_context(
            user_data_dir="chrome_profile",
            headless=True,
            executable_path=chrome_path,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--start-maximized",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ],
            viewport={"width": 1366, "height": 768},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/123.0.0.0 Safari/537.36",
        )
        page = browser.new_page()
        # Patch webdriver detection
        page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        page.add_init_script("window.chrome = { runtime: {} };")

        logger.info("🌐 Visiting homepage to establish session")
        page.goto("https://support.checkpoint.com", timeout=60000)
        time.sleep(8)

        for adv in tqdm(advisories, desc="Processing advisories"):
            adv_id = adv.get("id")
            sk_id = adv.get("skId")
            src = f"{ADVISORY_SOURCE_BASE_URL}{adv_id}"
            if src in existing: continue

            scraped = {}
            if sk_id:
                url = f"{ADVISORY_SCRAPE_BASE_URL}{sk_id}"
                scraped = fetch_page_and_parse(page, url)

            adv["published"] = convert_timestamp(adv.get("published"))
            adv["updated"] = convert_timestamp(adv.get("updated"))
            final = {**adv, **scraped}

            try:
                insert_advisory(conn, src, final)
                inserted += 1
            except Exception as e:
                logger.error(f"DB insert failed {src}: {e}")
            time.sleep(random.uniform(1.5, 3.0))

        logger.info(f"✅ Inserted {inserted} new advisories")
        browser.close()
    conn.close()
    logger.info("🎯 Done.")

if __name__ == "__main__":
    main()
