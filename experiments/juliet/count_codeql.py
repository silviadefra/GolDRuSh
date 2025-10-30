import os
import csv
import re

FUNC_HEADER_REGEX = re.compile(r'^(?:[a-zA-Z_][a-zA-Z0-9_\s\*:&<>]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*\)\s*(\{)?')

def get_function_ranges(c_file):
    functions = []
    func_name, start = None, None
    brace_depth = 0

    with open(c_file, 'r', errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        if func_name is None:
            match = FUNC_HEADER_REGEX.match(line.strip())
            if match:
                func_name = match.group(1)
                start = i
                if match.group(2):
                    brace_depth = 1
                else:
                    brace_depth = 0  # wait for opening brace in next lines
        else:
            # Count braces
            brace_depth += line.count("{")
            brace_depth -= line.count("}")

            if brace_depth == 0:
                functions.append((func_name, start, i))
                func_name, start = None, None

    return functions

def check_lines(csv_file, c_file):
    # Extract function ranges
    functions = get_function_ranges(c_file)

    found_bad = False
    found_good = False

    with open(csv_file, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 6:
                continue
            try:
                line_num = int(row[5])
            except ValueError:
                continue

            # check which function contains this line
            for func_name, start, end in functions:
                if start <= line_num <= end:
                    if "bad" in func_name:
                        found_bad = True
                    elif "good" in func_name:
                        found_good = True
                    break

    return found_bad, found_good

target_dir = "target_dir"  # folder with CSV files
source_dir = "cwe122"         # folder with .c/.cpp files

total_bad = 0
total_good = 0

for filename in os.listdir(target_dir):
    if filename.startswith("results_") and filename.endswith(".csv"):
        base = filename[len("results_"):-4]  # extract <File> with extension (.c or .cpp)
        csv_file = os.path.join(target_dir, filename)
        source_file = os.path.join(source_dir, base)

        if os.path.exists(source_file):
            found_bad, found_good = check_lines(csv_file, source_file)
            if found_bad:
                total_bad += 1
            if found_good:
                total_good += 1
        else:
            print(f"No matching source file found for {csv_file}")

print(f"Files with bad matches: {total_bad}")
print(f"Files with good matches: {total_good}")

