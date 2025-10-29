#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

TARGET_DIR="$1"

# QUERY='{free($ptr); not:$ptr=_; not:free($ptr); _($ptr);}'
QUERY='{free($ptr); not:$ptr=_; free($ptr);}'
OUTPUT_DIR="weggli_results"
mkdir -p "$OUTPUT_DIR"

for file in $(find "$TARGET_DIR" -type f \( -name "*.c" -o -name "*.cpp" \)); do
    base=$(basename "$file")
    result_file="$OUTPUT_DIR/result_${base}.txt"

    echo "Analyzing $file ..."
    if [[ "$file" == *.cpp ]]; then
        if ! ./target/release/weggli "$QUERY" --cpp "$file"> "$result_file" 2>&1; then
     echo " !! Weggli failed on $file, skipping"
     rm -f "$result_file"
     continue
     fi
    else
        if ! ./target/release/weggli "$QUERY" "$file"> "$result_file" 2>&1; then
     echo " !! Weggli failed on $file, skipping"
     rm -f "$result_file"
     continue
     fi
    fi

    echo " -> Results stored in $result_file"
done