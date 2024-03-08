# `GolDRuSh`: Goal-Driven Rule-Based vulnerability Search engine

This framework is a goal-driven, rule-based vulnerability detection tool that can detect code vulnerabilities in real programs.
`GolDRuSh` implements a
concolic vulnerability research strategy to identify vulnerabilities and generate PoC.
Developed in Python, it consists of two phases:

* Preparation: identifies
potentially vulnerable instructions and generates the inputs for the following phase.
* Test Execution Environment: generates tests that trigger the vulnerable code.


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
an expressive *rules language*.

### Preparation Phase

1. **Input Setup**: Two inputs are processed, i.e., the target executable (`target_executable`) and a set of
vulnerability rules(`rules_file`).
2. **Symbolic Execution**: Run the framework's preparation phase to set up the symbolic execution environment using `angr`.
3. **Setup for TEE**:Create the reachability conditions and
the labeled call graph for the TEE.

### TEE Phase

1. **Test Execution**: Execute tests on the instrumented application and trace execution paths using `frida`.
2. **Fitness Function**: Calculate the distance from each test to the target vulnerability as part of the genetic algorithm's evaluation process.
3. **Genetic Algorithm**: Utilize the genetic algorithm to create new tests.
4. **PoC Generation**: Automatically generate Proof of Concepts (PoC) for detected vulnerabilities.

### Running the Framework

To run the framework, execute the following command in your terminal:

```bash
python main_code.py <target_executable> <rules_file>
```

## Configuration

1. Configure [angr](https://github.com/angr) for symbolic execution in the preparation phase.
2. Configure [frida](https://github.com/frida) for test execution
and tracing in the TEE phase.