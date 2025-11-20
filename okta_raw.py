# okta_raw.py (Production Version)
import os
import logging
import requests
import psycopg2
from psycopg2.extras import Json, execute_values
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("okta_fetcher")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Okta"
BASE_URL = "https://trust.okta.com"
LIST_URL = f"{BASE_URL}/security-advisories/"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
MAX_WORKERS = 8

# --- Helper Functions ---
def get_existing_advisories(cur):
    """Fetches the source_urls of all existing Okta advisories from the staging table."""
    try:
        cur.execute("SELECT source_url FROM vendor_staging_table WHERE vendor_name = %s", (VENDOR_NAME,))
        return {row[0] for row in cur.fetchall()}
    except psycopg2.Error as e:
        logger.error(f"DB error fetching existing advisories: {e}")
        return set()

def get_all_advisory_urls(session):
    """Scrapes the main advisory list page to get URLs for all advisories."""
    logger.info(f"Fetching advisory list from {LIST_URL}...")
    try:
        response = session.get(LIST_URL, headers=HEADERS, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        advisory_list = soup.select("ul.css-7djl0f a.CustomLink")
        return {BASE_URL + a["href"] for a in advisory_list}
    except requests.RequestException as e:
        logger.error(f"Failed to fetch or parse the main advisory list: {e}")
        return set()

def fetch_advisory_detail(session, url):
    """Fetches and parses the content of a single advisory page."""
    try:
        response = session.get(url, headers=HEADERS, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        
        data = {"url": url}
        data["title"] = soup.select_one("h1").get_text(strip=True) if soup.select_one("h1") else None

        for section in soup.find_all("h3"):
            heading = section.get_text(strip=True).lower().replace(" ", "_")
            content_nodes = []
            for sibling in section.find_next_siblings():
                if sibling.name == "h3": break
                content_nodes.append(sibling)
            
            if "cve_details" in heading:
                table = next((s for s in content_nodes if s.name == 'table'), None)
                if table:
                    cve_info = {}
                    for row in table.find_all("tr"):
                        cells = row.find_all("td")
                        if len(cells) == 2:
                            key = cells[0].get_text(strip=True).replace(":", "")
                            value = cells[1].get_text(" ", strip=True)
                            cve_info[key] = value
                    data["cve_details"] = cve_info
            else:
                data[heading] = [elem.get_text(" ", strip=True) for elem in content_nodes if elem.get_text(strip=True)]

        return url, data
    except Exception as e:
        logger.warning(f"Failed to fetch or parse details for {url}: {e}")
        return url, None

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Fetcher...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn, requests.Session() as session:
            with conn.cursor() as cur:
                existing_advisories = get_existing_advisories(cur)

            all_advisory_urls = get_all_advisory_urls(session)
            urls_to_fetch = list(all_advisory_urls - existing_advisories)

            if not urls_to_fetch:
                logger.info("✅ All advisories are up to date.")
                return

            logger.info(f"Found {len(urls_to_fetch)} new advisories to download.")
            new_records = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future_to_url = {executor.submit(fetch_advisory_detail, session, url): url for url in urls_to_fetch}
                for future in tqdm(as_completed(future_to_url), total=len(urls_to_fetch), desc="Fetching Details"):
                    url, raw_data = future.result()
                    if raw_data:
                        new_records.append((VENDOR_NAME, url, Json(raw_data)))

            if new_records:
                with conn.cursor() as cur:
                    execute_values(cur, """
                        INSERT INTO vendor_staging_table (vendor_name, source_url, raw_data)
                        VALUES %s ON CONFLICT (source_url) DO NOTHING;
                    """, new_records)
                conn.commit()
                logger.info(f"✅ Fetching complete. Stored {len(new_records)} new advisories.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        if 'conn' in locals() and conn: conn.rollback()
    finally:
        logger.info(f"✅ {VENDOR_NAME} Fetcher finished.")

if __name__ == "__main__":
    main()