# Usage Guide

Detailed usage examples and tool documentation for both AI agents.

## General-Purpose Agent

### Starting the Agent

```bash
python src/local_agent.py
```

### Available Tools

#### web_search
DuckDuckGo web search for current information.

**Example queries:**
```
Search for the latest Python 3.12 release notes
What are the current best practices for LangChain agents?
Find recent articles about Ollama performance optimization
```

#### run_shell_command
Execute shell commands (blacklist-based security with injection protection).

**Blacklisted commands:** Destructive operations (rm, dd, shred), system modification (shutdown, reboot, sudo, chmod), network changes (iptables, ip, ifconfig), package management (apt, pip, npm, yum), code execution (python, bash, gcc, make), file downloads (wget, curl, git, rsync), database clients (mysql, psql, mongo), text editors (vim, nano, emacs), and other risky operations.

**Injection protection:** Blocks shell metacharacters and patterns that could enable command injection:
- Command chaining: `;`, `&&`, `||`
- Command substitution: `` ` ``, `$()`
- Dangerous redirects: `> /dev/`, `> /proc/`
- Piping to interpreters: `| bash`, `| python`
- Path bypasses: `/bin/rm`, `./rm` (basename extracted and checked)

**Example queries:**
```
What files are in my current directory?
What's today's date and system uptime?
Show me disk usage
List running Python processes
Check network connections with ss or netstat
Show environment variables with env
Find large files with du -h
```

**Note:** Simple pipes like `ps aux | grep python` are allowed, but pipes to interpreters are blocked for security.

#### search_files
Search file contents using grep (limited to .txt, .py, .md files).

**Example queries:**
```
Search for Python files containing 'def main'
Find all TODO comments in Python files
Search for 'langchain' in markdown files
```

#### find_files
Find files by name pattern (returns max 50 results).

**Example queries:**
```
Find all Python files in the current directory
Locate all markdown files
Find files with 'agent' in their name
```

#### read_file
Read contents of text files (max 1MB).

**Example queries:**
```
Read the contents of config.txt
Show me the README.md file
What's in local_agent.py?
```

#### get_system_info
Get system information (OS, CPU, memory, disk).

**Example queries:**
```
Show me system information
What are the system specs?
How much memory is available?
```

### Example Sessions

**File exploration:**
```
User: What Python files are in the src directory?
Agent: [Uses find_files to locate *.py in src/]

User: Show me what's in local_agent.py
Agent: [Uses read_file to display contents]

User: Find all functions that use the @tool decorator
Agent: [Uses search_files to grep for '@tool']
```

**System information:**
```
User: What's my system information and current disk usage?
Agent: [Uses get_system_info and run_shell_command with df]
```

**Research queries:**
```
User: Search for recent LangChain 1.0 migration guides
Agent: [Uses web_search to find articles]
```

### Interactive Commands

- `exit`, `quit`, `q` - Exit the agent
- `clear` - Clear conversation history

## Log Analysis Agent

### Starting the Agent

```bash
python src/log_analyzer.py
```

### Available Tools

#### fetch_remote_logs
SSH into remote servers (zeus, hera) and fetch logs via journalctl.

**Parameters:**
- server: "zeus" or "hera"
- service: apache2, nginx, postfix, dovecot, ssh, etc.
- lines: number of lines (default: 1000)
- since: time filter (e.g., "1 hour ago", "24 hours ago")

**Example queries:**
```
Fetch the last 1000 apache2 logs from zeus
Get error-level logs from hera for postfix from the last hour
Show me recent SSH authentication logs from both servers
```

#### create_log_summary
Generate statistical overview without raw logs (for large datasets).

**Use when:** Logs exceed context window capacity

**Example queries:**
```
Create a summary of the apache logs without showing raw data
Give me statistics on the log entries
Summarize the log patterns before detailed analysis
```

#### aggregate_logs
Reduce large log datasets to fit in context window.

**Aggregation methods:**
- `errors_only`: Filter to 401/403/404/500 codes, auth failures
- `sample`: First 100 + random middle 100 + last 100 lines
- `unique_ips`: One example per unique IP address
- `time_windows`: Distribute samples across time periods

**Example queries:**
```
Show me only the error entries from these logs
Sample the logs intelligently to reduce size
Show one example per unique IP address
```

#### analyze_log_patterns
Parse and analyze Apache/Nginx/Postfix/Dovecot logs.

**Detects:**
- Request patterns and frequencies
- Error distributions
- User agent patterns
- Geographic patterns (if IP data available)

**Example queries:**
```
Analyze these apache logs for attack patterns
Parse the nginx logs and identify suspicious activity
Look for brute force patterns in postfix logs
```

#### detect_anomalies
Statistical anomaly detection using z-score analysis.

**Example queries:**
```
Detect anomalies in request rates
Find unusual traffic patterns
Identify IPs with abnormal behavior
```

#### check_ip_reputation
Basic IP reputation checking.

**Example queries:**
```
Check the reputation of IP 192.168.1.100
Are any of these IPs known malicious?
Verify if this IP is suspicious
```

#### generate_fail2ban_rule
Generate fail2ban filter rules from detected patterns.

**Example queries:**
```
Generate a fail2ban rule for the SQL injection attempts
Create a filter rule for this attack pattern
Build fail2ban configuration for these suspicious requests
```

#### save_analysis_report
Save analysis results to file.

**Example queries:**
```
Save this analysis to a report file
Write the findings to analysis_report.txt
Export the results
```

### Example Sessions

**Basic log analysis:**
```
User: Analyze apache2 logs from zeus for the last 1000 lines
Agent: [Fetches logs using fetch_remote_logs]
Agent: [Creates summary using create_log_summary]
Agent: [Aggregates using errors_only method]
Agent: [Analyzes patterns using analyze_log_patterns]
Agent: [Reports findings]
```

**Brute force detection:**
```
User: Check logs from hera for brute force attempts on postfix service
Agent: [Fetches postfix logs]
Agent: [Analyzes patterns for repeated auth failures]
Agent: [Detects anomalies in request frequency]
Agent: [Reports IPs with suspicious behavior]

User: Generate a fail2ban rule for these attempts
Agent: [Uses generate_fail2ban_rule]
```

**Multi-server analysis:**
```
User: Look for unusual patterns in dovecot logs from both servers
Agent: [Fetches from zeus]
Agent: [Fetches from hera]
Agent: [Aggregates both datasets]
Agent: [Performs statistical anomaly detection]
Agent: [Compares patterns between servers]
```

**Sophisticated attack detection:**
```
User: Analyze for slow scanning attacks in the last 24 hours
Agent: [Fetches logs with since="24 hours ago"]
Agent: [Uses time_windows aggregation]
Agent: [Detects distributed patterns across time]
Agent: [Identifies coordinated IPs from same subnet]

User: Save the analysis
Agent: [Uses save_analysis_report]
```

### Context Management Workflow

For large log datasets (>10k lines), the agent automatically:

1. Creates statistical summary first (`create_log_summary`)
2. Aggregates logs using appropriate method:
   - `errors_only` for security analysis
   - `sample` for general overview
   - `unique_ips` for IP-based investigations
   - `time_windows` for temporal pattern analysis
3. Performs detailed analysis on reduced dataset
4. Reports findings with context

**Example large dataset query:**
```
User: Analyze all apache logs from zeus for the last week
Agent: [Fetches logs - notices large size]
Agent: [Creates summary showing 50K entries]
Agent: [Aggregates using errors_only - reduces to 2K entries]
Agent: [Performs detailed analysis]
Agent: [Reports security-relevant findings]
```

## Advanced Usage Patterns

### Iterative Investigation

```
User: Find suspicious activity in apache logs from zeus
Agent: [Initial analysis finds 3 suspicious IPs]

User: Check the reputation of those IPs
Agent: [Uses check_ip_reputation for each]

User: Show me all requests from the malicious IP
Agent: [Filters logs for specific IP]

User: Generate a fail2ban rule to block this pattern
Agent: [Creates rule based on detected pattern]

User: Save everything to a report
Agent: [Exports complete analysis]
```

### Comparative Analysis

```
User: Compare authentication failures between zeus and hera
Agent: [Fetches SSH logs from both servers]
Agent: [Analyzes patterns separately]
Agent: [Identifies differences in attack patterns]
Agent: [Reports comparative findings]
```

### Time-based Investigation

```
User: Show me how traffic patterns changed over the last 48 hours
Agent: [Fetches logs with time_windows aggregation]
Agent: [Performs temporal anomaly detection]
Agent: [Identifies when unusual patterns started]
Agent: [Reports timeline of events]
```

## Tips for Effective Use

### General Agent Tips
- Be specific about file paths when using read_file
- Use find_files first to locate files, then read_file to view them
- Combine tools: find files → search contents → read specific files
- Use web_search for current information not in local files

### Log Analyzer Tips
- Start with summaries for large datasets
- Use errors_only aggregation for security investigations
- Use time_windows for temporal pattern analysis
- Use unique_ips when investigating specific IP addresses
- Always save important findings with save_analysis_report
- Let the agent manage context - it will aggregate automatically
- Be specific about time ranges (e.g., "last 6 hours" vs "recent")

### Performance Optimization
- For general agent: Use specific queries to reduce tool iterations
- For log analyzer: Specify time ranges to limit data fetched
- Use aggregation methods appropriate to investigation type
- Clear conversation history periodically with `clear` command
