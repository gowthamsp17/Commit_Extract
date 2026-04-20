#!/usr/bin/env python3

import argparse
import pandas as pd
import os
import sys

# -------------------------------
# Helper: Load branch CSV
# -------------------------------
def load_branch_csv(branch, data_dir):
    file_map = {
        "5.10.y": "5.10.y_commits.csv",
        "6.1.y": "6.1.y_commits.csv",
        "6.12.y": "6.12.y_commits.csv",
    }

    if branch not in file_map:
        print(f"[ERROR] Unsupported branch: {branch}")
        sys.exit(1)

    path = os.path.join(data_dir, file_map[branch])
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)

    df = pd.read_csv(path)
    return df


# -------------------------------
# Helper: Normalize column names
# -------------------------------
def normalize_branch_df(df, branch):
    hash_col = f"{branch} Commit Hash"

    if hash_col not in df.columns:
        print(f"[ERROR] Expected column '{hash_col}' not found")
        sys.exit(1)

    df = df.rename(columns={hash_col: "hash"})
    df["hash"] = df["hash"].str.strip().str.lower()

    return df


# -------------------------------
# Helper: Extract CVE mapping
# -------------------------------
def load_cve_mapping(cve_file, branch):
    df = pd.read_csv(cve_file)

    commit_col = f"{branch} Fixed Commit"
    cve_col = "CVE Number"

    if commit_col not in df.columns:
        print(f"[ERROR] Column '{commit_col}' not found in CVE file")
        sys.exit(1)

    # Keep only relevant columns
    cve_df = df[[cve_col, commit_col]].dropna()

    # Normalize
    cve_df = cve_df.rename(columns={
        cve_col: "cve",
        commit_col: "hash"
    })

    cve_df["hash"] = cve_df["hash"].astype(str).str.strip().str.lower()

    # Handle multiple CVEs per commit
    cve_df = (
        cve_df.groupby("hash")["cve"]
        .apply(lambda x: ",".join(sorted(set(x))))
        .reset_index()
    )

    return cve_df


# -------------------------------
# Main logic
# -------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Kernel tool with CVE enrichment (LEFT JOIN support)"
    )

    parser.add_argument("--branch", required=True,
                        choices=["5.10.y", "6.1.y", "6.12.y"],
                        help="Kernel branch")

    parser.add_argument("--data-dir", default=".",
                        help="Directory containing CSV files")

    parser.add_argument("--with-cve", action="store_true",
                        help="Include CVE column (without filtering)")

    parser.add_argument("--only-cve", action="store_true",
                        help="Show only commits that have CVEs")

    parser.add_argument("--output", help="Output CSV file")

    args = parser.parse_args()

    # Load branch commits
    df = load_branch_csv(args.branch, args.data_dir)
    df = normalize_branch_df(df, args.branch)

    # If CVE enrichment requested
    if args.with_cve or args.only_cve:
        cve_file = os.path.join(args.data_dir, "cve_scraper.csv")
        if not os.path.exists(cve_file):
            print("[ERROR] cve_scraper.csv not found")
            sys.exit(1)

        cve_df = load_cve_mapping(cve_file, args.branch)

        # LEFT JOIN (this is what you wanted)
        df = df.merge(cve_df, on="hash", how="left")

        # Rename column to match your tool style
        df = df.rename(columns={"cve": "cves"})

    # Filter only CVE commits if requested
    if args.only_cve:
        df = df[df["cves"].notna()]

    # Output
    if args.output:
        df.to_csv(args.output, index=False)
        print(f"[INFO] Saved to {args.output}")
    else:
        print(df.head(20).to_string(index=False))


# -------------------------------
# Entry
# -------------------------------
if __name__ == "__main__":
    main()
