import os
import time
import json
import logging
import requests
import pandas as pd
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# --- Configuration ---
INPUT_SPREADSHEET = "Enriched CVEs.xlsx"
OUTPUT_SPREADSHEET = "Prioritized CVEs.xlsx"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
DATE_FORMAT = "%Y-%m-%d"

# --- Throttling Configuration ---
MAX_THREADS = 3
REQUEST_DELAY = 5.0  # 1 call every 5 seconds per thread

# --- LEV Calculation Configuration ---
EPSS_RELEVANCE_WINDOW_DAYS = 30

# --- Setup Logging ---
# This will log messages to both your console and a file named 'prioritization.log'
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler("prioritization.log")
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)

# Create console handler
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
logger.addHandler(stream_handler)


def fetch_epss_data(cve_id):
    """
    Fetches both the current EPSS score and the time-series data for a CVE.
    """
    time.sleep(REQUEST_DELAY)  # Enforce rate limit
    params = {'cve': cve_id, 'scope': 'time-series'}
    try:
        response = requests.get(EPSS_API_URL, params=params, timeout=20)
        if response.status_code == 429:
            logging.warning(f"Rate limit hit for {cve_id}. Retrying may be needed.")
            return cve_id, None, None

        response.raise_for_status()
        data = response.json()

        if data.get("status-code") == 200 and data.get("data"):
            cve_data = data["data"][0]
            current_epss = float(cve_data.get("epss", 0.0))

            time_series = {
                item['date']: float(item['epss'])
                for item in cve_data.get("time-series", [])
            }
            return cve_id, current_epss, time_series
        else:
            logging.warning(f"No EPSS data found for {cve_id}. Message: {data.get('message', 'N/A')}")
            return cve_id, None, None

    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {cve_id}: {e}")
        return cve_id, None, None
    except (KeyError, IndexError, TypeError) as e:
        logging.error(f"Error parsing EPSS data for {cve_id}: {e}")
        return cve_id, None, None

def weight_function(current_date, dn):
    """
    Calculates a simple linear weight.
    The closer the date is to the present (dn), the higher the weight.
    """
    total_days = EPSS_RELEVANCE_WINDOW_DAYS
    days_diff = (dn - current_date).days
    if days_diff < 0 or days_diff > total_days:
        return 0.0
    return 1.0 - (days_diff / total_days)

def calculate_lev(cve_id, d0_str, dn_str, epss_scores_for_cve):
    """
    Calculates the LEV score for a given CVE-ID.
    d0_str: CVE publication date (YYYY-MM-DD)
    dn_str: Current date (YYYY-MM-DD)
    epss_scores_for_cve: A dictionary of {date: score} for the last 30 days.
    """
    if not d0_str or pd.isna(d0_str):
        logging.warning(f"Missing publication date for {cve_id}, cannot calculate LEV.")
        return None

    try:
        d0 = datetime.datetime.strptime(str(d0_str).split(' ')[0], DATE_FORMAT)
        dn = datetime.datetime.strptime(dn_str, DATE_FORMAT)
    except ValueError as e:
        logging.error(f"Date parsing error for {cve_id}: {e}. d0_str: {d0_str}, dn_str: {dn_str}")
        return None

    product = 1.0

    # Iterate through the last 30 days to calculate the product term
    for i in range(EPSS_RELEVANCE_WINDOW_DAYS + 1):
        current_date_for_product = dn - datetime.timedelta(days=i)

        # Only consider dates on or after the publication date
        if current_date_for_product < d0:
            break

        date_str = current_date_for_product.strftime(DATE_FORMAT)
        epss_score = epss_scores_for_cve.get(date_str, 0.0)
        weight = weight_function(current_date_for_product, dn)
        term = 1.0 - (epss_score * weight)
        product *= term

    lev_score = 1.0 - product
    return round(lev_score, 6)

def main():
    logging.info(f"Reading data from '{INPUT_SPREADSHEET}'...")
    if not os.path.exists(INPUT_SPREADSHEET):
        logging.error(f"Input file not found: {INPUT_SPREADSHEET}. Please run the enrichment script first.")
        return

    try:
        df_enriched = pd.read_excel(INPUT_SPREADSHEET)
    except Exception as e:
        logging.error(f"Could not read the input file. Error: {e}")
        return

    cve_list = df_enriched['CVE ID'].dropna().unique().tolist()
    if not cve_list:
        logging.warning("No CVEs found in the input file.")
        return

    logging.info(f"Fetching EPSS data for {len(cve_list)} unique CVEs...")

    epss_data_map = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_cve = {executor.submit(fetch_epss_data, cve): cve for cve in cve_list}
        for future in tqdm(as_completed(future_to_cve), total=len(cve_list), desc="Fetching EPSS Data"):
            cve_id, current_epss, time_series = future.result()
            if current_epss is not None:
                epss_data_map[cve_id] = {
                    "current": current_epss,
                    "time_series": time_series
                }

    logging.info("Calculating LEV scores and preparing output sheets...")

    prioritized_list = []
    all_dates = set()

    # Collect all dates from all time series to create a consistent set of columns
    for cve_data in epss_data_map.values():
        if cve_data.get("time_series"):
            all_dates.update(cve_data["time_series"].keys())

    # Ensure we have the last 30 days, even if some are missing from the API
    today = datetime.datetime.now()
    for i in range(EPSS_RELEVANCE_WINDOW_DAYS):
        all_dates.add((today - datetime.timedelta(days=i)).strftime(DATE_FORMAT))

    sorted_dates = sorted(list(all_dates), reverse=True)[:EPSS_RELEVANCE_WINDOW_DAYS]

    time_series_list = []
    current_date_str = today.strftime(DATE_FORMAT)

    for index, row in df_enriched.iterrows():
        cve_id = row['CVE ID']
        epss_info = epss_data_map.get(cve_id)

        current_epss_score = None
        lev_score = None

        if epss_info:
            current_epss_score = epss_info.get("current")
            publication_date = row.get('Published Date')
            time_series_data = epss_info.get("time_series", {})

            lev_score = calculate_lev(cve_id, publication_date, current_date_str, time_series_data)

            # Prepare row for the EPSS Time Series sheet
            ts_row = {'CVE-ID': cve_id}
            for date_str in sorted_dates:
                ts_row[date_str] = time_series_data.get(date_str)
            time_series_list.append(ts_row)

        # Prepare row for the Prioritized CVEs sheet
        prioritized_list.append({
            'CVE-ID': cve_id,
            'CVSS Score': row.get('CVSS Score'),
            'CVSS Severity': row.get('CVSS Severity'),
            'EPSS Score': current_epss_score,
            'LEV Score': lev_score
        })

    df_prioritized = pd.DataFrame(prioritized_list)
    df_time_series = pd.DataFrame(time_series_list)

    logging.info(f"Writing data to '{OUTPUT_SPREADSHEET}'...")
    with pd.ExcelWriter(OUTPUT_SPREADSHEET, engine='openpyxl') as writer:
        df_prioritized.to_excel(writer, sheet_name='Prioritized CVEs', index=False)
        df_time_series.to_excel(writer, sheet_name='EPSS Time Series', index=False)

    logging.info("Process completed successfully.")

if __name__ == "__main__":
    main()