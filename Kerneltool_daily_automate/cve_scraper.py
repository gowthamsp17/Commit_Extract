"""
CVE Scraper for https://lists.openwall.net/linux-cve-announce/
Traverses CVE announcements for a given date range and outputs a structured CSV.
Uses parallel processing with (available CPUs / 2) workers.

Usage:
    python cve_scraper.py --start 2025-10-22 --end 2025-10-23 --output cves.csv

Requirements:
    pip install requests beautifulsoup4

Known page formats
──────────────────
Format A (2025+) — separate "fixed in" lines, full 40-char hashes:
    Issue introduced in 5.4 with commit <40-hex>
    fixed in 5.4.220 with commit <40-hex>
    fixed in 5.10.150 with commit <40-hex>

Format B (2024) — introduced + fixed on ONE line, short 12-char hashes:
    Issue introduced in 6.5 with commit <12-hex> and fixed in 6.5.4 with commit <12-hex>
    Issue introduced in 6.5 with commit <12-hex> and fixed in 6.6   with commit <12-hex>
"""

import argparse
import csv
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta

import requests
from bs4 import BeautifulSoup

BASE_URL        = "https://lists.openwall.net/linux-cve-announce"
KERNEL_GIT_BASE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id="

_print_lock = threading.Lock()

def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)


def get_worker_count() -> int:
    cpu_count = os.cpu_count() or 2
    workers   = max(1, cpu_count // 2)
    tprint(f"INFO  Detected {cpu_count} CPUs -> using {workers} parallel workers")
    return workers


# ── Fetch ─────────────────────────────────────────────────────────────────────

def fetch_page(url: str, retries: int = 3, delay: float = 1.0):
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.text
            return None
        except requests.RequestException as exc:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                tprint(f"  [WARN] Failed to fetch {url}: {exc}")
                return None


def is_no_such_message(html: str) -> bool:
    return "No such message" in html or "The request has failed" in html


# ── Regex patterns ────────────────────────────────────────────────────────────
#
# Both patterns accept 12–40 hex chars to handle:
#   - short hashes (12 chars) used in 2024 announcements
#   - full  hashes (40 chars) used in 2025 announcements

# Format B (2024): entire "Issue introduced … and fixed in …" on one line.
# We anchor on the full line so we only capture the FIXED side.
FORMAT_B = re.compile(
    r"Issue\s+introduced\s+in\s+[\d.]+\s+with\s+commit\s+[0-9a-f]{12,40}\s+"
    r"and\s+fixed\s+in\s+"
    r"([\d]+\.[\d]+(?:\.[\d]+)?)"        # fixed version  X.Y or X.Y.Z
    r"\s+with\s+commit\s+([0-9a-f]{12,40})",
    re.IGNORECASE,
)

# Format A (2025+): standalone "fixed in …" or "and fixed in …" lines.
FORMAT_A = re.compile(
    r"(?:and\s+)?fixed\s+in\s+"
    r"([\d]+\.[\d]+(?:\.[\d]+)?)"        # version  X.Y or X.Y.Z
    r"\s+with\s+commit\s+([0-9a-f]{12,40})",
    re.IGNORECASE,
)


# ── Parse ─────────────────────────────────────────────────────────────────────

def extract_branches(raw_text: str) -> dict:
    """
    Try Format B first (2024 inline style).
    If nothing found, fall back to Format A (2025 standalone style).
    Returns {(major, minor): {version, commit, git_link}}.
    """
    branches = {}

    for pattern in (FORMAT_B, FORMAT_A):
        for m in pattern.finditer(raw_text):
            version_str = m.group(1)
            commit_hash = m.group(2)
            parts       = version_str.split(".")
            major, minor = int(parts[0]), int(parts[1])
            branches[(major, minor)] = {
                "version":  version_str,
                "commit":   commit_hash,
                "git_link": KERNEL_GIT_BASE + commit_hash,
            }
        if branches:
            break   # stop at the first pattern that yields results

    return branches


def parse_cve_page(html: str):
    soup     = BeautifulSoup(html, "html.parser")
    pre_tags = soup.find_all("pre")
    raw_text = "\n".join(tag.get_text() for tag in pre_tags)
    if not raw_text.strip():
        raw_text = soup.get_text()

    subject_match = re.search(r"Subject:\s*(CVE-[\d-]+):\s*(.+)", raw_text)
    if not subject_match:
        return None

    cve_number  = subject_match.group(1).strip()
    description = subject_match.group(2).strip()
    branches    = extract_branches(raw_text)

    return {
        "cve_number":  cve_number,
        "description": description,
        "branches":    branches,
    }


# ── Per-URL worker ────────────────────────────────────────────────────────────

def fetch_and_parse(url: str):
    html = fetch_page(url)
    if html is None or is_no_such_message(html):
        return None

    parsed = parse_cve_page(html)
    if parsed is None:
        tprint(f"  [WARN] Could not parse CVE at {url}, skipping.")
        return None

    parsed["source_url"] = url
    tprint(f"  OK  {parsed['cve_number']}  ({len(parsed['branches'])} branches)  {url}")
    return parsed


# ── Day scraper ───────────────────────────────────────────────────────────────

def discover_max_index(day_str: str) -> int:
    """Exponential probe + binary search to find the highest valid index."""
    lo, hi = 1, 1

    while True:
        url  = f"{BASE_URL}/{day_str}/{hi}"
        html = fetch_page(url)
        if html is None or is_no_such_message(html):
            break
        lo  = hi
        hi *= 2
        if hi > 2000:
            hi = 2000
            break

    url  = f"{BASE_URL}/{day_str}/1"
    html = fetch_page(url)
    if html is None or is_no_such_message(html):
        return 0

    while lo < hi - 1:
        mid  = (lo + hi) // 2
        url  = f"{BASE_URL}/{day_str}/{mid}"
        html = fetch_page(url)
        if html is None or is_no_such_message(html):
            hi = mid
        else:
            lo = mid

    return lo


def scrape_day(day: date, executor: ThreadPoolExecutor):
    day_str = day.strftime("%Y/%m/%d")
    tprint(f"\nDATE [{day_str}] Discovering CVE count ...")

    max_idx = discover_max_index(day_str)
    if max_idx == 0:
        tprint(f"     [{day_str}] No CVEs found.")
        return []

    tprint(f"     [{day_str}] Fetching {max_idx} CVEs in parallel ...")

    urls          = [f"{BASE_URL}/{day_str}/{i}" for i in range(1, max_idx + 1)]
    future_to_url = {executor.submit(fetch_and_parse, url): url for url in urls}
    url_to_result = {}

    for future in as_completed(future_to_url):
        url = future_to_url[future]
        try:
            url_to_result[url] = future.result()
        except Exception as exc:
            tprint(f"  [ERROR] {url} raised {exc}")
            url_to_result[url] = None

    results = [url_to_result[url] for url in urls if url_to_result.get(url) is not None]
    tprint(f"     [{day_str}] Parsed {len(results)} CVEs")
    return results


# ── CSV building ──────────────────────────────────────────────────────────────

def collect_all_branch_keys(all_cves):
    keys = set()
    for cve in all_cves:
        keys.update(cve["branches"].keys())
    return sorted(keys)


def build_csv_headers(branch_keys):
    base = ["CVE Number", "Description", "Source URL"]
    for major, minor in branch_keys:
        prefix = f"{major}.{minor}.y"
        base  += [f"{prefix} Fixed Version", f"{prefix} Fixed Commit", f"{prefix} Git Link"]
    return base


def cve_to_row(cve, branch_keys):
    row = [cve["cve_number"], cve["description"], cve["source_url"]]
    for key in branch_keys:
        branch = cve["branches"].get(key, {})
        row   += [branch.get("version", ""), branch.get("commit", ""), branch.get("git_link", "")]
    return row


def write_csv(all_cves, output_path: str):
    branch_keys = collect_all_branch_keys(all_cves)
    file_exists = os.path.isfile(output_path)

    if file_exists:
        # Read existing headers to detect any previously seen branch columns
        with open(output_path, "r", newline="", encoding="utf-8") as f:
            reader      = csv.reader(f)
            old_headers = next(reader, [])

        # Reconstruct existing branch keys from old headers (3 cols per branch after base 3)
        old_branch_keys = []
        for i in range(3, len(old_headers), 3):
            match = re.match(r"(\d+)\.(\d+)\.y", old_headers[i])
            if match:
                old_branch_keys.append((int(match.group(1)), int(match.group(2))))

        # Merge: keep old column order, append any brand-new branches at the end
        merged_keys = old_branch_keys + [k for k in branch_keys if k not in old_branch_keys]
        headers     = build_csv_headers(merged_keys)

        if headers != old_headers:
            # New branch columns appeared — rewrite whole file with merged headers
            with open(output_path, "r", newline="", encoding="utf-8") as f:
                old_rows = list(csv.reader(f))          # includes header row

            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for row in old_rows[1:]:                # re-emit old data, pad if needed
                    writer.writerow(row + [""] * (len(headers) - len(row)))
                for cve in all_cves:
                    writer.writerow(cve_to_row(cve, merged_keys))
        else:
            # Headers unchanged — simple append, no header row written
            with open(output_path, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for cve in all_cves:
                    writer.writerow(cve_to_row(cve, merged_keys))

        print(f"\nAppended {len(all_cves)} CVEs -> {output_path}")
    else:
        # Fresh file
        headers = build_csv_headers(branch_keys)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for cve in all_cves:
                writer.writerow(cve_to_row(cve, branch_keys))

        print(f"\nWrote {len(all_cves)} CVEs -> {output_path}")

    print(f"Branches: {[f'{m}.{n}.y' for m, n in branch_keys]}")


# ── Entry point ───────────────────────────────────────────────────────────────

def iter_dates(start: date, end: date):
    current = start
    while current <= end:
        yield current
        current += timedelta(days=1)


def main():
    parser = argparse.ArgumentParser(
        description="Scrape Linux CVE announcements from lists.openwall.net"
    )
    parser.add_argument("--start",  required=True, help="Start date YYYY-MM-DD")
    parser.add_argument("--end",    default=None,  help="End date YYYY-MM-DD (inclusive, default: today)")
    parser.add_argument("--output", default="cves.csv", help="Output CSV path (default: cves.csv)")
    args = parser.parse_args()

    start_date = date.fromisoformat(args.start)
    end_date   = date.fromisoformat(args.end) if args.end else date.today()

    if start_date > end_date:
        print("Error: --start must be <= --end")
        return

    workers  = get_worker_count()
    all_cves = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for day in iter_dates(start_date, end_date):
            day_cves = scrape_day(day, executor)
            all_cves.extend(day_cves)

    if not all_cves:
        print("No CVEs found for the given date range.")
        return

    write_csv(all_cves, args.output)


if __name__ == "__main__":
    main()
