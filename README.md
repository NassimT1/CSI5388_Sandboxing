# CSI5388_Sandboxing

### **Overview**
This is a SQL injection detection system. It's different from other SQL injection detectors because
it looks at the behavior of the query, not the just what it looks like. It safely runs suspicious queries
inside a temporary, in-memory sqlite3 database to see if they actually act like an attack.

### **What It Does**
This SQL injection detection system runs suspicious queries in a controlled environment to see if
they behave like SQL injections. Here's how it does this.

1. AST Profiling: It starts by using a pre-computed abstract syntax tree (AST) profile to
    understand the structure of the query. It looks at things like the tables it's using and the way
    it is built.
2. Dynamic Database Creation: It creates a temporary sqlite3 database. It's designed to exactly
    fit the structure of the query it's running.
3. Canary Traps: It fills the database with special “trap” data. It's data that should not be
    returned unless something malicious is happening.
4. Execution & Monitoring: It runs the query and monitors it to see if it behaves suspiciously.
    The system flags the query if:
       o A UNION-based attack exposes any hidden “canary” data
       o A condition like OR 1=1, which forces all rows, including trap data, to be returned
       o Small changes in results, which indicates blind SQL injection techniques
5. Static Fallback: If the query is simply too broken to be executed, a strict set of regex-based
    checks are performed to catch obvious injection patterns.

### **Detection Categories**
The system groups any detected issues into a set of clear categories to make it easier to understand
what type of behavior was identified and why.

- union_based
- tautology
- blind_boolean
- blind_time
- stacked_queries
- comment_obfuscation
- encoding_obfuscation
- nested_injection

### **Command-Line Usage**
Use the test_sandbox.py script to test how the sandbox performs on data. The script can handle a
single CSV file that contains both original queries with labels and AST profile information.

**Standard Evaluation:**
```
python test_sandbox.py path/to/SQL_injection_Dataset_Feature_Extraction_Results.csv
```

**Limit Execution (evaluate only the first N rows):**
```
python test_sandbox.py path/to/SQL_injection_Dataset_Feature_Extraction_Results.csv --limit
2000
```

**Debug Mode (print False Positives and False Negatives):**
```
python test_sandbox.py path/to/SQL_injection_Dataset_Feature_Extraction_Results.csv --show-
fp --show-fn
```

**Adjust Debug Sample Size (default is 20):**
```
python test_sandbox.py path/to/SQL_injection_Dataset_Feature_Extraction_Results.csv --show-
fp --show-fn --sample 50
```


