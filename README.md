# `GolDRuSh`: Goal-Driven Rule-Based vulnerability Search engine

`GolDRuSh` is a goal-driven, rule-based vulnerability detection tool that actually works on real programs.
`GolDRuSh` implements a concolic vulnerability research strategy to identify vulnerabilities and generate working PoC exploits.
The main algorithm of `GolDRuSh` consists of two phases:

1. Preparation: identifies potentially vulnerable instructions and generates the inputs for the following phase.
2. Testing: generates tests to trigger the vulnerable code.


## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/silviadefra/GolDRuSh.git
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

`GolDRuSh` identifies vulnerabilities using
an expressive *rules language* (see folder `rules` for a few examples).

### Preparation Phase

1. **Input Setup**: Two inputs are processed, i.e., the target executable (`target_executable`) and a set of
vulnerability rules(`rules_file`).
2. **Symbolic Execution**: Run the framework's preparation phase to set up the symbolic execution environment using `angr`.
3. **Setup for TEE**:Create the reachability conditions and
the labeled call graph for the TEE.

### Testing Phase

1. **Test Execution**: Execute tests on the instrumented application and trace execution paths using `frida`.
2. **Fitness Function**: Calculate the distance from each test to the target vulnerability as part of the genetic algorithm's evaluation process.
3. **Genetic Algorithm**: Utilize the genetic algorithm to create new tests.
4. **PoC Generation**: Automatically generate Proof of Concept (PoC) exploits for the detected vulnerabilities.

### Running the Framework

To run the framework, execute the following command in your terminal:

```bash
python goldrush.py <target_executable> --rules <rules_file>
```

### Optional arguments with default values

```bash
usage: goldrush.py [-h] [--rules_file RULES_FILE] [--file_type [FILE_TYPE]]
                   [--num_values NUM_VALUES] [--num_best_fit NUM_BEST_FIT]
                   [--num_generations NUM_GENERATIONS] [--len_cache LEN_CACHE]
                   [--steps STEPS] [--tests TESTS [TESTS ...]] [--csv_file CSV_FILE]
                   binary

positional arguments:
  binary                The binary file to process

options:
  -h, --help            show this help message and exit
  --rules_file RULES_FILE
                        The rules file to use (default: rules.txt)
  --file_type [FILE_TYPE]
                        Flag indicating whether the binary is an executable (1) or a
                        library (0) (default: 1)
  --num_values NUM_VALUES
                        Number of symbolic solutions per function to compare with
                        concrete executions (default: 4)
  --num_best_fit NUM_BEST_FIT
                        Number of individuals in the population (default: 4)
  --num_generations NUM_GENERATIONS
                        Number of generations (default: 10000)
  --len_cache LEN_CACHE
                        Number of test cases to store for fitness caching (default:
                        100)
  --steps STEPS         Maximum number of steps from one API call of the rule to the
                        next (default: 8)
  --tests TESTS [TESTS ...]
                        List of test cases to be used (default: strings of randomly
                        lenght between 8 and 256)
  --csv_file CSV_FILE   The csv file to write the fitness
  ```

## Configuration

Make sure that the following tools are present and properly configured in your system.

1. [angr](https://github.com/angr) for symbolic execution in the preparation phase.
2. [frida](https://github.com/frida) for test execution and program tracing.