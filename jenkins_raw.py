# jenkins_raw.py (Production Version - Playwright Updated)
import os
import re
import time
import logging
import requests
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from playwright.sync_api import sync_playwright

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("jenkins_fetcher")
load_dotenv()

DB_CONFIG = {
    "dbname": os.getenv('DB_NAME'), "user": os.getenv('DB_USER'),
    "password": os.getenv('DB_PASS'), "host": os.getenv('DB_HOST'),
    "port": os.getenv('DB_PORT')
}
VENDOR_NAME = "Jenkins"
BASE_URL = "https://www.jenkins.io"
START_URL = "https://www.jenkins.io/security/advisories/"
MAX_WORKERS = 10

# --- DB & Scraping Helpers ---
def get_existing_urls(cur):
    urls = set()
    try:
        cur.execute("SELECT source_url FROM vendor_staging_table WHERE vendor_name = %s;", (VENDOR_NAME,))
        urls = {row[0] for row in cur.fetchall()}
        logger.info(f"Found {len(urls)} existing advisories in the database.")
    except psycopg2.Error as e:
        logger.warning(f"Could not fetch existing URLs. Error: {e}")
    return urls


def get_all_advisory_links_from_html():
    all_links = set()
    page_num = 1

    logger.info("Setting up Playwright to collect all advisory links...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto(START_URL, timeout=60000)

        while True:
            logger.info(f"Scanning link page {page_num}...")
            soup = BeautifulSoup(page.content(), 'html.parser')

            for link_tag in soup.select("a[href*='/security/advisory/']"):
                if href := link_tag.get('href'):
                    if re.search(r'/\d{4}-\d{2}-\d{2}/?$', href):
                        full_url = BASE_URL + href if not href.startswith('http') else href
                        all_links.add(full_url)

            # Try to click "Next" button
            try:
                next_button = page.locator("a.page-link[aria-label='Next']")
                if next_button.count() == 0 or not next_button.is_enabled():
                    logger.info("✅ No more 'Next' buttons found. All pages have been scanned.")
                    break

                next_button.click()
                page.wait_for_timeout(2000)  # 2 seconds delay to let content load
                page_num += 1

            except Exception as e:
                logger.info(f"✅ Pagination finished or no more pages. ({e})")
                break

        browser.close()

    return list(all_links)


def fetch_advisory_html(session, url):
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        return url, response.text
    except requests.RequestException as e:
        logger.warning(f"Failed to download {url}: {e}")
        return url, None


# --- Main Orchestrator ---
def main():
    logger.info("🚀 Starting Jenkins Fetcher...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                existing_urls = get_existing_urls(cursor)

            all_urls = get_all_advisory_links_from_html()
            urls_to_fetch = [url for url in all_urls if url not in existing_urls]

            if not urls_to_fetch:
                logger.info("✅ All advisories are up to date.")
                return
            
            logger.info(f"Found {len(urls_to_fetch)} new advisories to scrape.")
            
            all_data = []
            with requests.Session() as session:
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    future_to_url = {executor.submit(fetch_advisory_html, session, url): url for url in urls_to_fetch}
                    for future in tqdm(as_completed(future_to_url), total=len(urls_to_fetch), desc="Fetching Advisory HTML"):
                        url, html_content = future.result()
                        if html_content:
                            all_data.append((VENDOR_NAME, url, Json({"html_content": html_content})))
            
            if all_data:
                logger.info("Performing bulk insert into staging table...")
                with conn.cursor() as cursor:
                    execute_values(cursor, """
                        INSERT INTO vendor_staging_table (vendor_name, source_url, raw_data)
                        VALUES %s ON CONFLICT (source_url) DO UPDATE SET
                        raw_data = EXCLUDED.raw_data, processed = FALSE;
                    """, all_data)
                conn.commit()
                logger.info(f"Upserted {len(all_data)} records into the staging table.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
    finally:
        logger.info(f"✅ {VENDOR_NAME} Fetcher finished.")


if __name__ == "__main__":
    main()
