# Fortinet_raw.py (Definitive Production Version - Sequential)
import requests
from bs4 import BeautifulSoup
import psycopg2
from psycopg2.extras import Json, execute_values
import logging, sys, time, re
from dotenv import load_dotenv
import os
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

# --- Setup ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger(__name__)
load_dotenv()

# --- Configuration ---
DB_CONFIG = {
    "host": os.getenv("DB_HOST"), "port": os.getenv("DB_PORT"),
    "dbname": os.getenv("DB_NAME"), "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}
VENDOR_NAME = "Fortinet Networks"
BASE_URL = "https://www.fortiguard.com"
LISTING_URL = BASE_URL + "/psirt?page={page}&date=&severity=&product=&component=&version="

# --- DB & Scraping Helpers ---
def get_existing_advisory_urls():
    urls = set()
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT source_url FROM vendor_staging_table WHERE vendor_name = %s", (VENDOR_NAME,))
                urls = {row[0] for row in cur.fetchall()}
    except psycopg2.Error as e:
        logger.warning(f"Could not get existing URLs, proceeding with full scrape. Error: {e}")
    return urls

def scrape_detail(advisory_summary):
    if not advisory_summary.get("url"): return advisory_summary
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        res = requests.get(advisory_summary["url"], headers=headers, timeout=30)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        pub_tag = soup.find("td", string="Published Date")
        advisory_summary["published_date"] = pub_tag.find_next_sibling("td").get_text(strip=True) if pub_tag else ""
        cvss_tag = soup.find("td", string="CVSSv3 Score")
        advisory_summary["cvssv3_score"] = cvss_tag.find_next_sibling("td").get_text(strip=True) if cvss_tag else ""

        cve_tag = soup.find("td", string="CVE ID")
        if cve_tag and cve_tag.find_next_sibling("td"):
            cve_buttons = cve_tag.find_next_sibling("td").find_all("button")
            advisory_summary["cve_id_list"] = [b.get("data-cveid", "").strip() for b in cve_buttons if b.get("data-cveid")]
        
        solution_texts = []
        tables = soup.find_all("table")
        for table in tables:
            if (header := table.find("thead")) and "Solution" in header.get_text():
                if tbody := table.find("tbody"):
                    for tr in tbody.find_all("tr"):
                        tds = tr.find_all("td")
                        solution_texts.append(" | ".join(td.get_text(strip=True) for td in tds if td))
        advisory_summary["solution"] = "; ".join(solution_texts) if solution_texts else ""
    except Exception as e:
        logger.error(f"Error fetching detail for {advisory_summary['url']} -> {e}")
    return advisory_summary

def main():
    logger.info(f"🚀 Starting {VENDOR_NAME} Fetcher (Sequential)...")
    existing_urls = get_existing_advisory_urls()
    logger.info(f"Found {len(existing_urls)} existing advisories in database.")
    
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    options.add_argument(f'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    
    new_advisories_to_scrape = []
    try:
        page = 1
        keep_scanning = True
        with tqdm(desc="Scanning List Pages with Selenium") as pbar:
            while keep_scanning:
                driver.get(LISTING_URL.format(page=page))
                time.sleep(3) # A small static sleep is acceptable here
                
                soup = BeautifulSoup(driver.page_source, "html.parser")
                rows = soup.find_all("div", class_="row", onclick=True)

                if not rows:
                    logger.info(f"No advisories on page {page}. Stopping scan.")
                    break
                
                page_has_new = False
                for row in rows:
                    try:
                        detail_path = row.get("onclick", "").replace("location.href = '", "").replace("'", "")
                        if not detail_path:
                            continue
                        detail_url = BASE_URL + detail_path

                        ir_number = detail_path.split('/')[-1]

                        # --- Extract listing columns ---
                        desc_divs = row.find_all("div", class_="col-md-3")
                        description = desc_divs[1].small.get_text(strip=True) if len(desc_divs) > 1 and desc_divs[1].small else ""

                        prod_div = row.find("div", class_="col-md-2")
                        affected_products = [b.get_text(strip=True) for b in prod_div.find_all("b")] if prod_div else []

                        date_div = row.find("div", class_="col d-none d-lg-block")
                        updated_date = date_div.small.get_text(strip=True).replace("Published:", "").strip() if date_div and date_div.small else ""

                        comp_divs = row.find_all("div", class_="col d-none d-lg-block text-center")
                        component = comp_divs[0].get_text(strip=True) if len(comp_divs) > 0 else ""
                        severity = comp_divs[1].get_text(strip=True) if len(comp_divs) > 1 else ""

                        # --- Add new advisory if not existing ---
                        if detail_url not in existing_urls:
                            page_has_new = True
                            new_advisories_to_scrape.append({
                                "url": detail_url,
                                "ir_number": ir_number,
                                "description": description,
                                "affected_products": affected_products,
                                "updated_date": updated_date,
                                "component": component,
                                "severity": severity
                            })
                    except Exception as e:
                        logger.error(f"Error parsing row on page {page}: {e}")


                if not page_has_new and existing_urls:
                    logger.info(f"Page {page} contains only old advisories. Stopping delta-scan.")
                    keep_scanning = False
                
                page += 1
                pbar.update(1)
    except Exception as e:
        logger.error(f"An error occurred during the main list scrape: {e}")
    finally:
        driver.quit()

    if not new_advisories_to_scrape:
        logger.info("✅ No new advisories to fetch.")
        return

    unique_advisories_to_scrape = list({adv['url']: adv for adv in new_advisories_to_scrape}.values())
    logger.info(f"Found {len(unique_advisories_to_scrape)} new advisories. Scraping details sequentially...")
    
    # --- FIX: Replaced ThreadPoolExecutor with a sequential for loop ---
    detailed_advisories = []
    for advisory in tqdm(unique_advisories_to_scrape, desc="Scraping Details"):
        detailed_advisories.append(scrape_detail(advisory))
        time.sleep(0.5) # Be polite to the server

    if detailed_advisories:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cur:
                logger.info(f"Staging {len(detailed_advisories)} new advisories...")
                execute_values(cur, """
                    INSERT INTO vendor_staging_table (vendor_name, source_url, raw_data)
                    VALUES %s ON CONFLICT (source_url) DO UPDATE SET raw_data = EXCLUDED.raw_data, processed = FALSE;
                """, [(VENDOR_NAME, adv.get("url"), Json(adv)) for adv in detailed_advisories])
        logger.info("✅ Staging complete.")

if __name__ == "__main__":
    main()