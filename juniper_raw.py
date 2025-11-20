# juniper_raw_playwright.py (Enhanced - Full Data Capture)
import logging, sys, time, re, psycopg2, json, os
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

load_dotenv()
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT")),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASS")
}

TABLE_NAME = "vendor_staging_table"
VENDOR_NAME = "Juniper"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------- Playwright Setup ----------
def create_browser():
    p = sync_playwright().start()
    browser = p.chromium.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    return p, browser, context, page

# ---------- Extract Text Helper ----------
def extract_text_by_label(soup, label_name):
    """
    Finds text near a <label> tag or any heading that matches the given label.
    """
    try:
        if not soup:
            return "N/A"

        # Flexible label match
        label = soup.find(lambda tag: tag.name in ["label", "b", "strong", "span", "h2", "h3"]
                          and label_name.lower() in tag.get_text(strip=True).lower())

        if not label:
            return "N/A"

        # Look for the next content section
        next_el = label.find_next_sibling()
        if next_el:
            return " ".join(next_el.stripped_strings)

        # Sometimes inside <lightning-formatted-rich-text>
        rich = label.find_next("lightning-formatted-rich-text")
        if rich:
            return " ".join(rich.stripped_strings)

        return "N/A"
    except Exception:
        return "N/A"

def extract_cve_from_title(title):
    matches = re.findall(r"\b(CVE-\d{4}-\d+)\b", title)
    return ",".join(matches) if matches else None

def extract_cve_from_table(soup):
    table = soup.find("table")
    if not table:
        return "N/A"
    cves = []
    for row in table.find_all("tr")[1:]:
        td = row.find("td")
        if td:
            cve = td.get_text(strip=True)
            if cve:
                cves.append(cve)
    return ",".join(cves) if cves else "N/A"

# ---------- Scrape Advisory ----------
def scrape_advisory(page, title, link):
    try:
        page.goto(link, timeout=60000)
        time.sleep(4)
        soup = BeautifulSoup(page.content(), "html.parser")

        header = soup.find("div", class_="headerSection")
        section = soup.find("div", class_="section2")

        article_id = extract_text_by_label(header, "Article ID") or "N/A"
        created = extract_text_by_label(header, "Created")
        updated = extract_text_by_label(header, "Last Updated")

        cve = extract_cve_from_title(title) or extract_cve_from_table(soup)

        # Extract key sections similar to old script
        data = {
            "advisory_id": article_id,
            "title": title,
            "url": link,
            "cve_id": cve,
            "created": created,
            "last_updated": updated,
            "product_affected": extract_text_by_label(section, "Product Affected"),
            "severity": extract_text_by_label(section, "Severity"),
            "problem": extract_text_by_label(section, "Problem"),
            "solution": extract_text_by_label(section, "Solution"),
            "workaround": extract_text_by_label(section, "Workaround"),
            "severity_assessment": extract_text_by_label(section, "Severity Assessment"),
            "modification_history": extract_text_by_label(section, "Modification History"),
            "related_information": extract_text_by_label(section, "Related Information"),
            "severity_assessment_score": extract_text_by_label(section, "Severity Assessment (CVSS) Score"),
        }

        # Cleanup (standardize N/A)
        for key in data:
            if not data[key] or data[key].strip() == "":
                data[key] = "N/A"

        return data

    except PlaywrightTimeoutError:
        logging.error(f"Timeout loading {link}")
        return None
    except Exception as e:
        logging.error(f"Error scraping {link}: {e}")
        return None

# ---------- Batch Scrape ----------
def scrape_batch(advisories):
    p, browser, context, page = create_browser()
    results = []
    try:
        for title, link in advisories:
            row = scrape_advisory(page, title, link)
            if row:
                results.append(row)
    finally:
        context.close()
        browser.close()
        p.stop()
    return results

# ---------- DB Functions ----------
def get_existing_urls():
    urls = set()
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(f"SELECT source_url FROM {TABLE_NAME} WHERE vendor_name = %s;", (VENDOR_NAME,))
        urls = {r[0] for r in cur.fetchall()}
        cur.close()
        conn.close()
        logging.info(f"Found {len(urls)} existing advisories in DB.")
    except Exception as e:
        logging.warning(f"Could not fetch existing URLs: {e}")
    return urls

def insert_into_staging(data_list):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    for row in data_list:
        try:
            cur.execute(f"""
                INSERT INTO {TABLE_NAME} (vendor_name, source_url, raw_data)
                VALUES (%s, %s, %s)
                ON CONFLICT (source_url) DO NOTHING;
            """, (VENDOR_NAME, row.get("url"), json.dumps(row)))
        except Exception as e:
            logging.error(f"Insert error for {row.get('url')}: {e}")
    conn.commit()
    cur.close()
    conn.close()

# ---------- Main ----------
if __name__ == "__main__":
    BASE_URL = "https://supportportal.juniper.net/s/global-search/%40uri?language=en_IN#f-sf_primarysourcename=Knowledge&f-sf_articletype=Security%20Advisories&numberOfResults=100"

    existing_urls = get_existing_urls()
    p, browser, context, page = create_browser()
    advisory_list = []

    try:
        logging.info(f"Fetching Juniper Security Advisory listings...")
        page.goto(BASE_URL, timeout=60000)
        time.sleep(8)
        soup = BeautifulSoup(page.content(), "html.parser")
        advisories = soup.select("a[aria-label='Navigate to the record']")
        for a_tag in advisories:
            title = a_tag.get_text(strip=True)
            href = a_tag.get("href")
            if href:
                full_url = "https://supportportal.juniper.net" + href
                if full_url not in existing_urls:
                    advisory_list.append((title, full_url))
        logging.info(f"Collected {len(advisory_list)} advisories for verification.")
    finally:
        context.close()
        browser.close()
        p.stop()

    if not advisory_list:
        logging.info("✅ No new advisories found.")
        sys.exit(0)

    # Scrape and insert
    all_data = scrape_batch(advisory_list)
    insert_into_staging(all_data)
    logging.info(f"✅ Staging complete. {len(all_data)} advisories inserted.")
