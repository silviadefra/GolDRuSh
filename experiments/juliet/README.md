# Experiments on Juliet

[Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/112?page=2) consists of a large set of C/C++ programs covering 118 different CWEs, systematically designed to provide both vulnerable and safe code variants.
Every vulnerable function contains the word `bad` and every safe function contains the word `good`.

For comparison, we selected two representative tools [`Weggli`](https://github.com/weggli-rs/weggli) and [`CodeQL`](https://codeql.github.com/).


## Dataset Preparation

We selected only the test cases corresponding to the following CWEs:

- **CWE-122: Heap-Based Buffer Overflow.**
    The software writes data beyond the boundaries of allocated heap memory, potentially leading to memory corruption.
- **CWE-415: Double Free.** The software attempts to free the same memory region more than once, which may corrupt memory management structures.
- **CWE-416: Use After Free.** The software accesses memory after it has been freed, which may cause crashes or unexpected behavior.

The Windows-specific test cases were not included in our experiments.


## Rules Tested

- For our tool we tested the complete set of rules that we designed `rules/rules.txt`.
- For `CodeQL` we used the queries documented in the [official CodeQL coverage for C and C++](https://codeql.github.com/codeql-query-help/cpp-cwe/).
- For `Weggli` we adopted the patterns published in the public repository [weggli-patterns](https://github.com/0xdea/weggli-patterns). Note that no rules for CWE-122 are provided in that repository.


## Running the Frameworks

### SVDL

To obtain one executable for each test case, we relied on the official Juliet Makefile. Thus, running the following command for each directory.

```bash
make INCLUDE_MAIN=-DINCLUDEMAIN individuals
```

To execute the experiments we put all the executables in a directory (`targets`) and used the `run_svdl.sh` script.

```bash
./run_svdl.sh <volume_path>
```

Note that this script requires our `Dockerfile` and `requirements.txt`.

### CodeQL

We took only non-Window-specific test cases, producing 3 folders for each CWE considered.
We placed them and the `testcasesupport` folder of the Juliet dataset in the same folder and used the `run_codeql.sh` script.

```bash
./run_codeql.sh <targate_dir> <database_dir>
```

Note that for each folder containing test cases of different CWEs, we used a separate script. However, for simplicity, we only share the one used for CWE-122, since the only differences between scripts are the specific rules applied. The rules for the other CWEs are included in the script as comments.

### Weggli

We took only non-Window-specific test cases, producing 2 folders for each CWE considered.
For each folder we used the `run_weggli.sh` script.

```bash
./run_codeql.sh <targate_dir>
```

Note that for each folder containing test cases of different CWEs, we used a separate script. However, for simplicity, we only share the one used for CWE-415, since the only differences between scripts are the specific rules applied. The rules for the CWE-416 are included in the script as comments.

## Evaluation 

### Metrics 

For each CWE, we record the number of true positives (TP), false positives (FP), and false negatives (FN). A true positive corresponds to a correctly identified vulnerability, a false positive to a reported vulnerability that is not actually present, and a false negative to a missed vulnerability that is in fact present.

### Analysis

Each of the three tools generates one output file per test case.
- For the tools SVDL and `Weggli`, the output files list which functions are detected as vulnerable. Since vulnerable and safe functions are named using the words *"bad"* and *"good"*, respectively, we examine each output file to check for the presence of these words.
- For `CodeQL`, the output files specify the line of code of the vulnerability detected. Therefore, to determine whether the reported vulnerability was located within a bad or good function, we needed to cross-reference the results with the source code (`count_codeql.py`).

## Results

In general, each Juliet test case is
designed to contain a single vulnerability, with the exception of two files for CWE-415 and one file for CWE-416 that contain no vulnerabilities at all (for example CWE416_Use_After_Free__operator_equals_01_good1.cpp).


<table>
  <tr>
    <th rowspan="2">CWE ID</th>
    <th rowspan="2">Test Cases</th>
    <th colspan="3" style="text-align:center;">SVDL</th>
    <th colspan="3" style="text-align:center;">CodeQL</th>
    <th colspan="3" style="text-align:center;">Weggli</th>
  </tr>
  <tr>
    <th>TP</th><th>FP</th><th>FN</th>
    <th>TP</th><th>FP</th><th>FN</th>
    <th>TP</th><th>FP</th><th>FN</th>
  </tr>
  <tr>
    <td>CWE-122</td><td>3870</td><td>417</td><td>0</td><td>3453</td><td>251</td><td>0</td><td>3619</td><td>*</td><td>*</td><td>*</td>
  </tr>
  <tr>
    <td>CWE-415</td><td>820</td><td>220</td><td>0</td><td>598</td><td>204</td><td>0</td><td>614</td><td>90</td><td>5</td><td>728</td>
  </tr>
  <tr>
    <td>CWE-416</td><td>394</td><td>55</td><td>0</td><td>338</td><td>105</td><td>0</td><td>288</td><td>113</td><td>10</td><td>280</td>
  </tr>
</table>

