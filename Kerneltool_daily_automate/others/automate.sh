#!/bin/bash

# Force script to run from its own directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Create timestamped log file
LOG_FILE="run_$(date +%Y-%m-%d_%H-%M-%S).txt"

# Redirect all output (stdout + stderr) to both terminal and file
exec > >(tee -a "$LOG_FILE") 2>&1

REPO=/home/gowtham-23345/Linux_Stable/linux
SCRIPT=./find_versions_auto.sh
PYTHON_SCRIPT=./kernel_commit_csv.py
CVE_SCRIPT=./cve_scraper.py

NO_FILES=NO_files_final.txt
NO_DIRS=NO_directories_final.txt

SERVER_INFO=/home/gowtham-23345/server_info
CVE_FILE=cve_scraper.csv

SERIES_LIST=("5.10" "6.1" "6.12")

# Summary storage
declare -A SUMMARY_COMMITS
declare -A SUMMARY_LAST_VER
declare -A SUMMARY_LATEST_VER

CVE_NEW_COUNT=0
CVE_START_DATE=""

echo "======================================="
echo "[*] Updating Linux repository"
echo "======================================="

git -C "$REPO" pull --ff-only || {
    echo "[!] git pull failed"
    exit 1
}

git -C "$REPO" fetch --tags

echo "[✓] Repository updated"
echo

# =========================
# Kernel Processing Section
# =========================
for series in "${SERIES_LIST[@]}"; do
    echo "======================================="
    echo "[*] Processing $series.y"
    echo "======================================="

    log_file="logs-${series}.y.txt"
    output_csv="${series}.y_commits.csv"

    if [[ ! -f "$log_file" ]]; then
        echo "[!] Log file not found, skipping $series.y"
        continue
    fi

    # Count before
    before_count=$(wc -l < "$log_file")

    last_ver=$(tail -n 1 "$log_file" | awk '{print $1}')
    echo "[*] Last processed version: $last_ver"

    latest_ver=$(git -C "$REPO" tag -l "v${series}.*" | sort -V | tail -1)

    if [[ -z "$latest_ver" ]]; then
        echo "[!] No tags found for $series.y"
        continue
    fi

    echo "[*] Latest available version: $latest_ver"

    SUMMARY_LAST_VER[$series]="$last_ver"
    SUMMARY_LATEST_VER[$series]="$latest_ver"

    if [[ "$last_ver" == "${latest_ver#v}" || "$last_ver" == "$latest_ver" ]]; then
        echo "[✓] Already up-to-date"
        SUMMARY_COMMITS[$series]=0
        echo
        continue
    fi

    start_version="v${last_ver#v}"

    echo "[*] Updating logs from $start_version → $latest_ver"

    $SCRIPT "$REPO" "$start_version" >> "$log_file"

    # Count after
    after_count=$(wc -l < "$log_file")

    new_commits=$((after_count - before_count))
    SUMMARY_COMMITS[$series]=$new_commits

    echo "[*] New commits added: $new_commits"

    config_file=$(ls "$SERVER_INFO"/config-${series}.* 2>/dev/null | sort -V | tail -1)

    if [[ -z "$config_file" ]]; then
        echo "[!] Config not found"
        continue
    fi

    python3 "$PYTHON_SCRIPT" \
        --repo "$REPO" \
        --no-files "$NO_FILES" \
        --no-dirs "$NO_DIRS" \
        --output "$output_csv" \
        --branch "${series}.y:origin/linux-${series}.y:${config_file}" \
        --file "$log_file" \
        --parallel

    echo "[✓] Done for $series.y"
    echo
done

# =========================
# CVE Processing Section
# =========================

echo "======================================="
echo "[*] CVE Scraping"
echo "======================================="

if [[ ! -f "$CVE_FILE" ]]; then
    start_date="2020-01-01"
    before_cve_count=0
else
    before_cve_count=$(wc -l < "$CVE_FILE")

    last_line=$(tail -n 1 "$CVE_FILE")
    last_date=$(echo "$last_line" | grep -oE '[0-9]{4}[-/][0-9]{2}[-/][0-9]{2}' | head -1)

    last_date=$(echo "$last_date" | tr '/' '-')
    start_date=$(date -d "$last_date +1 day" +%Y-%m-%d)
fi

CVE_START_DATE="$start_date"

echo "[*] CVE start date: $start_date"

today=$(date +%Y-%m-%d)

start_ts=$(date -d "$start_date" +%s)
today_ts=$(date -d "$today" +%s)

if (( start_ts <= today_ts )); then
    python3 "$CVE_SCRIPT" \
        --start "$start_date" \
        --output "$CVE_FILE"

    after_cve_count=$(wc -l < "$CVE_FILE")
    CVE_NEW_COUNT=$((after_cve_count - before_cve_count))
else
    echo "[✓] CVE already up-to-date"
    CVE_NEW_COUNT=0
fi

# =========================
# FINAL SUMMARY
# =========================

echo
echo "======================================="
echo "            FINAL SUMMARY              "
echo "======================================="

for series in "${SERIES_LIST[@]}"; do
    echo "Branch: $series.y"
    echo "  Last Version   : ${SUMMARY_LAST_VER[$series]}"
    echo "  Latest Version : ${SUMMARY_LATEST_VER[$series]}"
    echo "  New Commits    : ${SUMMARY_COMMITS[$series]}"
    echo
done

echo "CVE Summary:"
echo "  Start Date : $CVE_START_DATE"
echo "  New CVEs   : $CVE_NEW_COUNT"

echo "======================================="
echo "[✓] FULL AUTOMATION COMPLETED"
echo "======================================="
