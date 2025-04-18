# Example Rule Specification
In this document, we illustrate how a rule of `rules/rules.txt` file is written following the specific grammar of `grammar.py` . Below is an example rule:
```text
# CWE-122
b1 = malloc(m) , read(?,b2,n) ;
b1 == b2 AND m < n ;
```
## Rule Structure
Each `rule` is composed of either three or two parts: the **string declaration** (`string`), the **signature** (`sign`) and the **predicate** (`pred`) or only the **signature** (`sign`) and the **predicate** (`pred`).

  In the example above there is no **string declaration**.

- **String Declaration**: This is a list of parameters for which we need the values as strings.

  Usually , the string declaration appears before the signature and has the following format:
  ```text
  string a, b, c;
  ```
  where `a`,`b` and `c` are parameters

- **Signature**: This is a finite sequence of API calls `api` separated by a comma. Each API call consists of:

  - Return variable
  - API name
  - A list of parameters

  In the example above, the signature includes the following API calls:
  - `b1 = malloc(m)`
  - `read(?,b2,n)`
  
  Notice that irrelevant variables can be neglected and are replaced with the symbol `?`.
- **Predicate**: This is a boolean formula, which can include:
  - **Standard operators** such as negation and conjunction.
  - **Comparisons** between arithmetic expressions. These expressions may contain:
    - Variables
    - Constants
    - Classical operators
  
  In this case, the predicate is a conjunction of conditions:
  ```text
  b1 == b2 AND m < n 
  ```
## Creating the Rule
The rule was created after analyzing the examples provided by the [Mitre](https://cwe.mitre.org/), specifically those concerning the [CWE-122](https://cwe.mitre.org/data/definitions/122.html).