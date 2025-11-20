# fedoraraw.py (Production Version - Corrected)
import os
import logging
import json
import re
import psycopg2
from psycopg2.extras import Json, execute_values
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# --- Setup & Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s')
logger = logging.getLogger("fedora_fetcher")
load_dotenv()

DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'), 'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'), 'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}
VENDOR_NAME = "Fedora"
BASE_URL = "https://linuxsecurity.com"
MAIN_URL = f"{BASE_URL}/advisories/fedora"
MAX_WORKERS = 10
ITEMS_PER_PAGE = 20
HEADERS = {'User-Agent': 'Mozilla/5.0'}

# --- Database Helpers ---
def get_existing_urls(cur):
    urls = set()
    try:
        cur.execute("SELECT source_url FROM vendor_staging_table WHERE vendor_name = %s;", (VENDOR_NAME,))
        urls = {row[0] for row in cur.fetchall()}
        logger.info(f"Found {len(urls)} existing advisories in the database.")
    except psycopg2.Error as e:
        logger.warning(f"Could not fetch existing URLs from database. Error: {e}")
    return urls

# --- Scraping Logic (Your Core Logic) ---
def _get_total_pages():
    try:
        response = requests.get(MAIN_URL, headers=HEADERS, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')
        pagination = soup.find('ul', class_='pagination')
        if not pagination: return 1
        end_link = pagination.find('a', title='End')
        if end_link and 'href' in end_link.attrs:
            start_match = re.search(r'start=(\d+)', end_link['href'])
            if start_match:
                return (int(start_match.group(1)) // ITEMS_PER_PAGE) + 1
        # Fallback if 'End' link is not found
        page_numbers = [int(a.text) for a in pagination.select('a') if a.text.isdigit()]
        return max(page_numbers) if page_numbers else 1
    except requests.RequestException as e:
        logger.error(f"Error determining total pages: {e}")
        return 0

def fetch_page_links(page_num):
    page_url = f"{MAIN_URL}?start={(page_num - 1) * ITEMS_PER_PAGE}"
    try:
        response = requests.get(page_url, headers=HEADERS, timeout=20)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')
        page_links = set()
        main_content = soup.find('main', id='sp-component') or soup.find('div', class_='view-category')
        if main_content:
            for link_tag in main_content.select('h2.sej-ptitle a, div.cat-item-title a'):
                if href := link_tag.get('href'):
                    page_links.add(f"{BASE_URL}{href}")
        return page_links
    except Exception:
        return set()

def fetch_all_bulletin_links(existing_urls):
    total_pages = _get_total_pages()
    if total_pages == 0: return []
    
    all_bulletin_links = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_page_links, page): page for page in range(1, total_pages + 1)}
        for future in tqdm(as_completed(futures), total=total_pages, desc="Scanning Pages"):
            all_bulletin_links.update(future.result())
    
    new_links = [link for link in all_bulletin_links if link not in existing_urls]
    logger.info(f"Found {len(all_bulletin_links)} unique links on site, {len(new_links)} of which are new.")
    return new_links

def _parse_cves_from_text(text):
    """Your original, working CVE parser."""
    cves = []
    matches = re.findall(r'\*\s+(CVE-\d{4}-\d{4,7}):\s+(.*)', text)
    if matches:
        for cve_id, description in matches:
            cves.append({"id": cve_id.strip(), "description": description.strip()})
        return cves
    matches = re.findall(r'(CVE-\d{4}-\d{4,7})', text)
    return [{"id": cve_id, "description": None} for cve_id in matches]

def parse_advisory_details(url):
    """Your original, robust advisory detail parser."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'lxml')

        structured_data = {}
        
        title_tag = soup.select_one('#advisory-main h1.sppb-addon-title')
        raw_text_tag = soup.select_one('#advisorycontent pre')
        gray_box = soup.find('div', class_='whitebg gray')
        
        titled_sections = {}
        for section_box in soup.find_all('div', class_='whitebg no-r'):
            if title_tag_h3 := section_box.find('h3', class_='sppb-addon-title'):
                title_text = title_tag_h3.get_text(strip=True).lower().replace(' ', '_')
                if content := section_box.find('div', class_='sppb-addon-content'):
                    titled_sections[title_text] = content.get_text(strip=True, separator='\n')

        structured_data['title'] = title_tag.get_text(strip=True) if title_tag else "Title not found"
        raw_text = raw_text_tag.get_text() if raw_text_tag else ""
        if not raw_text: return {"source_url": url, "error": "No raw text found."}
        
        structured_data['advisory_id'] = (m.group(0) if (m := re.search(r'FEDORA-\d{4}-\w+', raw_text)) else None)
        structured_data['issue_date'] = (m.group(1) if (m := re.search(r'(\d{4}-\d{2}-\d{2}\s[\d:.]+\+\d{2}:\d{2})', raw_text)) else None)

        structured_data['package_details'] = {}
        if gray_box:
            for drow in gray_box.find_all('div', class_='drow'):
                text = ' '.join(drow.get_text(strip=True).split())
                if ':' in text:
                    key, val = text.split(':', 1)
                    structured_data['package_details'][key.strip().lower().replace(' ', '_')] = val.strip()

        # Your robust logic for finding Update Information
        summary_block_text = titled_sections.get('summary', '')
        update_info_text = ''
        if 'Update Information:' in summary_block_text:
            parts = summary_block_text.split('Update Information:', 1)
            update_info_text = parts[1].strip()
        else:
            update_info_raw_match = re.search(r'Update Information:\s*\n(.*?)\n----', raw_text, re.DOTALL)
            if update_info_raw_match:
                update_info_text = update_info_raw_match.group(1).strip()
        
        structured_data['update_information'] = {"text": update_info_text, "cves": _parse_cves_from_text(update_info_text)}
        structured_data['update_instructions'] = titled_sections.get('update_instructions')

        return {"source_url": url, "structured_data": structured_data}
    except Exception as e:
        return {"source_url": url, "error": f"Failed to parse details: {e}"}

# --- Main Orchestrator ---
def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Fetcher...")
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                existing_urls = get_existing_urls(cursor)

            bulletin_links = fetch_all_bulletin_links(existing_urls)
            if not bulletin_links:
                logger.info("✅ All advisories are up to date.")
                return

            all_advisories = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(parse_advisory_details, url): url for url in bulletin_links}
                for future in tqdm(as_completed(futures), total=len(bulletin_links), desc="Scraping Details"):
                    if (result := future.result()):
                        all_advisories.append(result)

            if all_advisories:
                logger.info("Performing bulk insert into staging table...")
                values = [(VENDOR_NAME, adv['source_url'], Json(adv)) for adv in all_advisories if adv.get("source_url") and not adv.get("error")]
                if values:
                    with conn.cursor() as cursor:
                        execute_values(cursor, """
                            INSERT INTO vendor_staging_table (vendor_name, source_url, raw_data)
                            VALUES %s ON CONFLICT (source_url) DO NOTHING;
                        """, values)
                    conn.commit()
                    logger.info(f"Inserted {len(values)} new records into the staging table.")
    
    except Exception as e:
        logger.error(f"An unexpected error occurred in main: {e}", exc_info=True)
    finally:
        logger.info(f"✅ {VENDOR_NAME} Fetcher finished.")

if __name__ == "__main__":
    main()