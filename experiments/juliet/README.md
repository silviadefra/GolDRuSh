# Experiments on Juliet

[Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/112?page=2) consists of a large set of C/C++ programs covering 118 different CWEs, systematically designed to provide both vulnerable and safe code variants.

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
- For `Weggli` we adopted the patterns published in the public repository [weggli-patterns](https://github.com/0xdea/weggli-patterns).


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