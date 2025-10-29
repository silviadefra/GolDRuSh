#!/bin/bash
set -euo pipefail

TARGET_DIR=$1
DB_DIR=$2
SUPPORT_DIR="testcasesupport"
SUPPORT_FILES="$SUPPORT_DIR/io.c $SUPPORT_DIR/std_thread.c"

for file in "$TARGET_DIR"/*; do
    # only process .c and .cpp
    if [[ "$file" == *?.c ]]; then
        # simple case, single C file
        instruction="gcc -I$SUPPORT_DIR -DINCLUDEMAIN $SUPPORT_FILES $file"

    elif [[ "$file" == *a.c ]]; then
        # multi-file C case (replace a.c with *.c)
        prefix="${file%a.c}"
        f="${prefix}*.c"
        instruction="gcc -I$SUPPORT_DIR -DINCLUDEMAIN $SUPPORT_FILES $f"

    elif [[ "$file" == *?.cpp ]]; then
        # simple case, single C++ file
        instruction="g++ -I$SUPPORT_DIR -DINCLUDEMAIN $SUPPORT_FILES $file"

    elif [[ "$file" == *a.cpp ]]; then
        # multi-file C++ case (replace a.cpp with *.cpp)
        prefix="${file%a.cpp}"
        f="${prefix}*.cpp"
        instruction="g++ -I$SUPPORT_DIR -DINCLUDEMAIN $SUPPORT_FILES $f"

    else
        echo "Skipping non-C/C++ file: $file"
        continue
    fi

    base=$(basename "$file")
    db_path="$DB_DIR"
    results="results/results_${base}.csv"

    echo "Analyzing $file ..."

    # delete database directory if it exists
    if [ -d "$db_path" ]; then
        echo " -> removing old database directory $db_path"
        rm -rf "$db_path"
    fi

    echo " -> creating database at $db_path"
    if ! ./codeql database create "$db_path" --language=cpp --command="$instruction"; then
        echo " !! Failed to create database for $file, skipping"
        continue
    fi
    
    # CWE415 queries:codeql/cpp-queries:experimental/Security/CWE/CWE-476/DangerousUseOfExceptionBlocks.ql codeql/cpp-queries:experimental/Security/CWE/CWE-415/DoubleFree.ql codeql/cpp-queries:Critical/DoubleFree.ql
    # CWE416 queries:codeql/cpp-queries:Security/CWE/CWE-416/IteratorToExpiredContainer.ql codeql/cpp-queries:Security/CWE/CWE-416/UseOfStringAfterLifetimeEnds.ql codeql/cpp-queries:Security/CWE/CWE-416/UseOfUniquePointerAfterLifetimeEnds.ql codeql/cpp-queries:Critical/UseAfterFree.ql
    echo " -> analyzing database"
    ./codeql database analyze "$db_path" codeql/cpp-queries:Security/CWE/CWE-131/NoSpaceForZeroTerminator.ql codeql/cpp-queries:Security/CWE/CWE-119/OverflowBuffer.ql codeql/cpp-queries:Critical/SizeCheck.ql codeql/cpp-queries:Critical/SizeCheck.ql --format=csv --output="$results" || {
        echo " !! Failed to analyze $file, skipping"
        continue
    }

    echo " -> results stored in $results"
done

