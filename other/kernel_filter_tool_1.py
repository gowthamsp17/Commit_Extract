#!/usr/bin/env python3
"""
Kernel Commit Filter Tool
=========================
Filters 5.10.y / 6.1.y / 6.12.y commit CSVs and the CVE scraper CSV
based on interactive prompts. Prints a summary to stdout and saves
results to CSV and/or Excel.

Usage:
    python3 kernel_filter_tool.py

Dependencies:
    pip install pandas openpyxl tabulate
"""

import os
import sys
import pandas as pd
from datetime import datetime

# ── Optional pretty-print ──────────────────────────────────────────────────
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ── File paths — edit these to match your local directory ─────────────────
DATA_FILES = {
    "5.10.y": "5.10.y_commits.csv",
    "6.1.y":  "6.1.y_commits.csv",
    "6.12.y": "6.12.y_commits.csv",
}
CVE_FILE = "cve_scraper.csv"

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]
APPLICABILITY_VALUES = ["y-applicable", "m-applicable", "Not applicable", "File in NO list"]

SEP = "─" * 60


# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════

def banner(text: str):
    print(f"\n{'═'*60}")
    print(f"  {text}")
    print(f"{'═'*60}")


def section(text: str):
    print(f"\n{SEP}")
    print(f"  {text}")
    print(SEP)


def prompt_choice(question: str, options: list, multi: bool = False, allow_all: bool = True) -> list:
    """Present a numbered menu; return list of chosen values."""
    print(f"\n{question}")
    if allow_all:
        print("  0) All (no filter)")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")

    while True:
        raw = input("  Enter number(s) separated by commas: ").strip()
        if raw == "0" and allow_all:
            return []          # empty list = no filter applied
        try:
            picks = [int(x.strip()) for x in raw.split(",") if x.strip()]
            chosen = [options[p - 1] for p in picks if 1 <= p <= len(options)]
            if chosen:
                return chosen
        except (ValueError, IndexError):
            pass
        print("  ⚠  Invalid input, try again.")


def prompt_text(question: str, allow_empty: bool = True) -> str:
    val = input(f"\n{question}: ").strip()
    if not val and not allow_empty:
        print("  ⚠  Value required.")
    return val


def prompt_yes_no(question: str) -> bool:
    while True:
        ans = input(f"\n{question} [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  ⚠  Please enter y or n.")


def load_commit_file(branch: str) -> pd.DataFrame | None:
    path = DATA_FILES[branch]
    if not os.path.exists(path):
        print(f"  ⚠  File not found: {path}")
        return None
    print(f"  Loading {branch} …", end=" ", flush=True)
    df = pd.read_csv(path, low_memory=False)
    print(f"{len(df):,} rows")
    return df


def load_cve_file() -> pd.DataFrame | None:
    if not os.path.exists(CVE_FILE):
        print(f"  ⚠  CVE file not found: {CVE_FILE}")
        return None
    print(f"  Loading CVE data …", end=" ", flush=True)
    df = pd.read_csv(CVE_FILE, low_memory=False)
    print(f"{len(df):,} rows")
    return df


def print_df(df: pd.DataFrame, max_rows: int = 30):
    """Print dataframe to terminal, truncated if large."""
    if df.empty:
        print("\n  (no results)")
        return
    display = df.head(max_rows)
    if HAS_TABULATE:
        print("\n" + tabulate(display, headers="keys", tablefmt="simple", showindex=False))
    else:
        print("\n" + display.to_string(index=False))
    if len(df) > max_rows:
        print(f"\n  … {len(df) - max_rows:,} more rows not shown (saved to file)")


def save_results(results: dict, base_name: str, save_csv: bool, save_excel: bool):
    """Save result dataframes to disk."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []

    if save_csv:
        for label, df in results.items():
            fname = f"{base_name}_{label.replace('.', '_')}_{ts}.csv"
            df.to_csv(fname, index=False)
            saved.append(fname)
            print(f"  ✔  Saved CSV  → {fname}  ({len(df):,} rows)")

    if save_excel:
        fname = f"{base_name}_{ts}.xlsx"
        with pd.ExcelWriter(fname, engine="openpyxl") as writer:
            for label, df in results.items():
                sheet = label[:31]           # Excel sheet name limit
                df.to_excel(writer, sheet_name=sheet, index=False)
        saved.append(fname)
        print(f"  ✔  Saved Excel → {fname}  ({sum(len(d) for d in results.values()):,} total rows, {len(results)} sheet(s))")

    return saved


# ══════════════════════════════════════════════════════════════════
# Filter engines
# ══════════════════════════════════════════════════════════════════

def apply_commit_filters(
    df: pd.DataFrame,
    branch: str,
    commit_hashes: list,
    severities: list,
    subsystems: list,
    applicabilities: list,
    cve_commits: set | None,
) -> pd.DataFrame:
    """Apply all active filters to a commit dataframe."""
    hash_col  = f"{branch} Commit Hash"
    applic_col = f"{branch} Applicability"

    mask = pd.Series(True, index=df.index)

    # Commit hash lookup (supports both full and short/prefix hashes)
    if commit_hashes:
        hashes_lower = [h.lower() for h in commit_hashes]
        full_hashes = df[hash_col].str.lower()
        def hash_matches(fh):
            return any(fh.startswith(h) or h.startswith(fh) for h in hashes_lower)
        mask &= full_hashes.apply(hash_matches)

    # Severity
    if severities:
        mask &= df["Severity"].isin(severities)

    # Subsystem (substring match, case-insensitive)
    if subsystems:
        sub_mask = pd.Series(False, index=df.index)
        for s in subsystems:
            sub_mask |= df["Subsystem"].fillna("").str.lower().str.contains(s.lower())
        mask &= sub_mask

    # Applicability
    if applicabilities:
        mask &= df[applic_col].isin(applicabilities)

    # CVE cross-reference: keep only commits whose hash starts with a CVE short hash
    if cve_commits is not None:
        full_hashes = df[hash_col].str.lower()
        # match if the full hash starts with any short hash from CVE file
        def matches_any(h):
            return any(h.startswith(s) for s in cve_commits)
        mask &= full_hashes.apply(matches_any)

    return df[mask].copy()


def get_cve_commits_for_branch(cve_df: pd.DataFrame, branch: str) -> set:
    """Return set of commit hash prefixes that have a CVE fix for the given branch.
    CVE file stores short hashes; we return them lowercased for prefix matching."""
    col = f"{branch} Fixed Commit"
    if col not in cve_df.columns:
        return set()
    return set(cve_df[col].dropna().astype(str).str.lower().str.strip())


def enrich_with_cve(result_df: pd.DataFrame, cve_df: pd.DataFrame, branch: str) -> pd.DataFrame:
    """Attach CVE numbers to matching commit rows using prefix matching (CVE short hash vs full hash)."""
    hash_col   = f"{branch} Commit Hash"
    commit_col = f"{branch} Fixed Commit"
    if commit_col not in cve_df.columns or result_df.empty:
        return result_df

    # Build {short_hash -> "CVE-1, CVE-2"} map
    cve_map_df = cve_df[["CVE Number", commit_col]].dropna(subset=[commit_col]).copy()
    cve_map_df["_short"] = cve_map_df[commit_col].astype(str).str.lower().str.strip()
    short_to_cves = cve_map_df.groupby("_short")["CVE Number"].apply(lambda x: ", ".join(x)).to_dict()

    def find_cves(full_hash: str) -> str | None:
        fh = str(full_hash).lower()
        matched = [cves for short, cves in short_to_cves.items() if fh.startswith(short)]
        return ", ".join(matched) if matched else None

    result_df = result_df.copy()
    result_df["Matched CVEs"] = result_df[hash_col].apply(find_cves)
    return result_df


def filter_cve_by_cve_number(cve_df: pd.DataFrame, cve_numbers: list) -> pd.DataFrame:
    """Filter CVE dataframe by CVE number list."""
    nums_upper = [c.upper() for c in cve_numbers]
    return cve_df[cve_df["CVE Number"].str.upper().isin(nums_upper)].copy()


# ══════════════════════════════════════════════════════════════════
# Output column selector
# ══════════════════════════════════════════════════════════════════

def select_output_columns(df: pd.DataFrame, branch: str) -> pd.DataFrame:
    """Keep the most relevant columns for a clean unified output."""
    hash_col   = f"{branch} Commit Hash"
    link_col   = f"{branch} GitHub Link"
    ver_col    = f"{branch} First Version"
    applic_col = f"{branch} Applicability"

    core = [hash_col, link_col, ver_col, "Description", "Subsystem",
            "Files Changed", "CONFIG_ Parameters", applic_col,
            "Severity", "Severity Reason", "Backport Status",
            "Cc stable", "Cc security"]

    # fix columns
    fix_cols = [c for c in df.columns if c.startswith("Fix-") and "Commit Hash" in c]
    fix_desc = [c for c in df.columns if c.startswith("Fix-") and "Description" in c]

    # CVE enrichment column if present
    cve_col = ["Matched CVEs"] if "Matched CVEs" in df.columns else []

    keep = [c for c in core + fix_cols + fix_desc + cve_col if c in df.columns]
    return df[keep]


# ══════════════════════════════════════════════════════════════════
# Main interactive flow
# ══════════════════════════════════════════════════════════════════

def main():
    banner("Kernel Commit Filter Tool")

    # ── Step 1: Primary input mode ────────────────────────────────
    section("Step 1 — Primary input mode")
    input_mode = prompt_choice(
        "How do you want to search?",
        ["By kernel branch (browse & filter)", "By commit hash(es)", "By CVE number(s)"],
        allow_all=False,
    )[0]

    # ── Step 2: Which branches to query ───────────────────────────
    section("Step 2 — Kernel branches")
    branch_choices = prompt_choice(
        "Which kernel branch(es)?",
        list(DATA_FILES.keys()),
        multi=True,
    )
    branches = branch_choices if branch_choices else list(DATA_FILES.keys())

    # ── Step 3: Commit hash input (if mode=hash) ──────────────────
    commit_hashes = []
    if input_mode == "By commit hash(es)":
        raw = prompt_text("Enter commit hash(es) separated by commas")
        commit_hashes = [h.strip() for h in raw.split(",") if h.strip()]

    # ── Step 4: CVE number input (if mode=CVE) ────────────────────
    cve_numbers = []
    if input_mode == "By CVE number(s)":
        raw = prompt_text("Enter CVE number(s) separated by commas (e.g. CVE-2023-1234)")
        cve_numbers = [c.strip() for c in raw.split(",") if c.strip()]

    # ── Step 5: Filters ───────────────────────────────────────────
    section("Step 3 — Filters")

    severities = prompt_choice(
        "Filter by Severity? (0 = all)",
        SEVERITY_ORDER,
        multi=True,
    )

    subsystem_raw = prompt_text(
        "Filter by Subsystem? Enter keyword(s) comma-separated (e.g. net, usb) or leave blank for all"
    )
    subsystems = [s.strip() for s in subsystem_raw.split(",") if s.strip()]

    applicabilities = prompt_choice(
        "Filter by Applicability? (0 = all)",
        APPLICABILITY_VALUES,
        multi=True,
    )

    do_cve_xref = prompt_yes_no("Cross-reference with CVE data? (only show commits that have a CVE fix)")

    # ── Step 6: Output options ────────────────────────────────────
    section("Step 4 — Output options")
    max_print = 30
    try:
        n = input("\n  Max rows to print to terminal [default 30]: ").strip()
        if n:
            max_print = int(n)
    except ValueError:
        pass

    save_csv   = prompt_yes_no("Save results to CSV file(s)?")
    save_excel = prompt_yes_no("Save results to Excel file?")
    output_name = prompt_text("Base name for output files [default: kernel_results]") or "kernel_results"

    # ══════════════════════════════════════════════════════════════
    # Load data
    # ══════════════════════════════════════════════════════════════
    section("Loading data …")

    cve_df = None
    if do_cve_xref or cve_numbers:
        cve_df = load_cve_file()

    commit_dfs = {}
    for branch in branches:
        df = load_commit_file(branch)
        if df is not None:
            commit_dfs[branch] = df

    if not commit_dfs:
        print("\n  ✖  No commit data loaded. Exiting.")
        sys.exit(1)

    # ══════════════════════════════════════════════════════════════
    # CVE-number mode: show CVE rows + derive commit hashes
    # ══════════════════════════════════════════════════════════════
    cve_result = pd.DataFrame()
    if cve_numbers and cve_df is not None:
        cve_result = filter_cve_by_cve_number(cve_df, cve_numbers)
        section(f"CVE lookup — {len(cve_result):,} matching CVE record(s)")
        print_df(cve_result[["CVE Number", "Description"] +
                             [f"{b} Fixed Commit" for b in branches if f"{b} Fixed Commit" in cve_result.columns]],
                 max_rows=max_print)

        # Derive commit hashes from CVE results to filter commit files
        for branch in branches:
            col = f"{branch} Fixed Commit"
            if col in cve_result.columns:
                hashes = cve_result[col].dropna().astype(str).tolist()
                commit_hashes.extend(hashes)
        commit_hashes = list(set(commit_hashes))

    # ══════════════════════════════════════════════════════════════
    # Apply filters to each branch
    # ══════════════════════════════════════════════════════════════
    all_results = {}

    for branch, df in commit_dfs.items():
        cve_commit_set = None
        if do_cve_xref and cve_df is not None:
            cve_commit_set = get_cve_commits_for_branch(cve_df, branch)

        filtered = apply_commit_filters(
            df, branch,
            commit_hashes=commit_hashes,
            severities=severities,
            subsystems=subsystems,
            applicabilities=applicabilities,
            cve_commits=cve_commit_set,
        )

        # Enrich with CVE numbers
        if cve_df is not None:
            filtered = enrich_with_cve(filtered, cve_df, branch)

        # Select clean output columns
        filtered = select_output_columns(filtered, branch)

        # Add branch label column
        filtered.insert(0, "Branch", branch)

        all_results[branch] = filtered

    # ══════════════════════════════════════════════════════════════
    # Print results
    # ══════════════════════════════════════════════════════════════
    banner("Results")

    total = sum(len(d) for d in all_results.values())
    print(f"\n  Total matching commits: {total:,}\n")

    for branch, df in all_results.items():
        section(f"{branch} — {len(df):,} commit(s)")

        # Summary stats
        if not df.empty and "Severity" in df.columns:
            sev_counts = df["Severity"].value_counts()
            print("  Severity breakdown:")
            for s in SEVERITY_ORDER:
                if s in sev_counts:
                    print(f"    {s:<12} {sev_counts[s]:>6,}")

        if not df.empty and "Matched CVEs" in df.columns:
            with_cve = df["Matched CVEs"].notna().sum()
            print(f"  Commits with CVE match: {with_cve:,}")

        print_df(df, max_rows=max_print)

    # ══════════════════════════════════════════════════════════════
    # Unified / combined output
    # ══════════════════════════════════════════════════════════════
    combined = pd.concat(all_results.values(), ignore_index=True) if all_results else pd.DataFrame()

    # ══════════════════════════════════════════════════════════════
    # Save to disk
    # ══════════════════════════════════════════════════════════════
    section("Saving output …")

    save_map = dict(all_results)
    if len(branches) > 1:
        save_map["combined"] = combined

    if not save_csv and not save_excel:
        print("  (no files saved — print only mode)")
    else:
        save_results(save_map, output_name, save_csv, save_excel)

    # Also save CVE lookup result if applicable
    if not cve_result.empty and (save_csv or save_excel):
        cve_save = {"CVE_lookup": cve_result}
        save_results(cve_save, output_name + "_cve", save_csv, save_excel)

    banner("Done")
    print(f"  Branches queried : {', '.join(branches)}")
    print(f"  Filters applied  :")
    print(f"    Severity       : {severities or 'All'}")
    print(f"    Subsystem      : {subsystems or 'All'}")
    print(f"    Applicability  : {applicabilities or 'All'}")
    print(f"    CVE xref       : {'Yes' if do_cve_xref else 'No'}")
    print(f"    Commit hashes  : {len(commit_hashes)} provided" if commit_hashes else "    Commit hashes  : None")
    print(f"  Total results    : {total:,} commit(s)\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Cancelled by user.")
        sys.exit(0)
