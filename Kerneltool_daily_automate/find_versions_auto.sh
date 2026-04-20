#!/bin/bash

src="$1"
start="$2"

cd "$src" || exit 1

# Extract series: v6.1 / v6.12 / v5.10
series=$(echo "$start" | cut -d'.' -f1,2)

# Extract start number
start_num=$(echo "$start" | cut -d'.' -f3)

# Validate input
if [[ -z "$start_num" ]]; then
#    echo "Error: Invalid start version (example: v6.1.5)"
    exit 1
fi

# Get all tags in this series and extract numbers
latest_num=$(git tag -l "${series}.*" \
    | sed "s/${series}.//" \
    | grep -E '^[0-9]+$' \
    | sort -n \
    | tail -1)

if [[ -z "$latest_num" ]]; then
#    echo "Error: No tags found for series $series"
    exit 1
fi

# echo "Detected latest version: ${series}.${latest_num}"

# Loop from start → latest
for ((i=start_num+1; i<=latest_num; i++)); do
    prev="${series}.$((i-1))"
    curr="${series}.${i}"
    ver="${curr#v}"

    # Skip if tag doesn't exist (just in case)
    if git rev-parse "$curr" >/dev/null 2>&1; then
        git log "${prev}..${curr}" --reverse --format="${ver} %H %s"
    fi
done
