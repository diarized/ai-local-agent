#!/usr/bin/env python3

"""
AI-Powered Log Analysis Agent
Detects unusual patterns in web server and mail server logs
Goes beyond fail2ban regex patterns to find sophisticated attacks
"""

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
import subprocess
import os
import re
import shlex
import hashlib
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import json

# ============================================================================
# PAGINATION SYSTEM
# ============================================================================

# Global cache for paginated data
# Structure: {data_id: {"content": full_text, "pages": [page1, page2, ...], "timestamp": time}}
_pagination_cache = {}

def _generate_data_id(text: str) -> str:
    """Generate a unique ID for cached data"""
    timestamp = str(time.time())
    return hashlib.md5(f"{text[:100]}{timestamp}".encode()).hexdigest()[:8]

def _cleanup_old_cache(max_age_seconds: int = 300):
    """Remove cache entries older than max_age_seconds (default: 5 minutes)"""
    current_time = time.time()
    to_remove = [
        data_id for data_id, data in _pagination_cache.items()
        if current_time - data["timestamp"] > max_age_seconds
    ]
    for data_id in to_remove:
        del _pagination_cache[data_id]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def estimate_tokens(text: str) -> int:
    """Rough estimation of token count (1 token ≈ 4 characters)"""
    return len(text) // 4

def check_context_size(text: str, max_tokens: int = 8000) -> tuple:
    """Check if text fits in context window and return (fits, token_count)"""
    tokens = estimate_tokens(text)
    return (tokens <= max_tokens, tokens)

def paginate_output(text: str, max_tokens_per_page: int = 6000, tool_name: str = "tool") -> str:
    """Paginate output to fit within token limits.

    Args:
        text: The text to paginate
        max_tokens_per_page: Maximum tokens per page (default: 6000)
        tool_name: Name of the tool for the message

    Returns:
        First page with instructions to get more data if needed
    """
    tokens = estimate_tokens(text)

    # If it fits in one page, return as-is
    if tokens <= max_tokens_per_page:
        return text

    # Clean up old cache entries
    _cleanup_old_cache()

    # Split into pages (by characters, approximating tokens)
    chars_per_page = max_tokens_per_page * 4
    pages = []

    # Split by lines to avoid breaking in the middle of a line
    lines = text.split('\n')
    current_page = []
    current_size = 0

    for line in lines:
        line_size = len(line) + 1  # +1 for newline

        if current_size + line_size > chars_per_page and current_page:
            # Page is full, save it
            pages.append('\n'.join(current_page))
            current_page = [line]
            current_size = line_size
        else:
            current_page.append(line)
            current_size += line_size

    # Don't forget the last page
    if current_page:
        pages.append('\n'.join(current_page))

    # Generate unique ID and cache the data
    data_id = _generate_data_id(text)
    _pagination_cache[data_id] = {
        "content": text,
        "pages": pages,
        "timestamp": time.time(),
        "tool_name": tool_name
    }

    # Return first page with pagination info
    total_pages = len(pages)
    first_page = pages[0]

    pagination_info = f"\n\n{'=' * 60}\n"
    pagination_info += f"📄 PAGINATED OUTPUT (Page 1 of {total_pages})\n"
    pagination_info += f"{'=' * 60}\n"
    pagination_info += f"Data ID: {data_id}\n"
    pagination_info += f"Total size: ~{tokens} tokens ({total_pages} pages)\n"
    pagination_info += f"Page size: ~{estimate_tokens(first_page)} tokens\n"
    pagination_info += f"\n💡 To see more data, use:\n"
    pagination_info += f"   get_more_data(data_id='{data_id}', page=2)\n"
    pagination_info += f"   get_more_data(data_id='{data_id}', page=3)\n"
    pagination_info += f"   ... up to page {total_pages}\n"
    pagination_info += f"{'=' * 60}"

    return first_page + pagination_info

# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

@tool
def get_more_data(data_id: str, page: int) -> str:
    """Retrieve additional pages from paginated tool output.

    When a tool returns paginated output, use this to get subsequent pages.

    Args:
        data_id: The data ID from the pagination message
        page: Page number to retrieve (2, 3, 4, etc.)
    """
    # Clean up old cache
    _cleanup_old_cache()

    if data_id not in _pagination_cache:
        return f"Error: Data ID '{data_id}' not found or expired. Cached data expires after 5 minutes."

    cached = _pagination_cache[data_id]
    pages = cached["pages"]
    total_pages = len(pages)

    if page < 1 or page > total_pages:
        return f"Error: Page {page} out of range. Valid pages: 1-{total_pages}"

    # Pages are 0-indexed internally, but 1-indexed for user
    page_content = pages[page - 1]

    header = f"{'=' * 60}\n"
    header += f"📄 PAGINATED OUTPUT (Page {page} of {total_pages})\n"
    header += f"{'=' * 60}\n"
    header += f"Data ID: {data_id}\n"
    header += f"Tool: {cached['tool_name']}\n"

    if page < total_pages:
        footer = f"\n\n{'=' * 60}\n"
        footer += f"💡 More data available. To see page {page + 1}, use:\n"
        footer += f"   get_more_data(data_id='{data_id}', page={page + 1})\n"
        footer += f"{'=' * 60}"
    else:
        footer = f"\n\n{'=' * 60}\n"
        footer += f"✓ End of data (page {total_pages} of {total_pages})\n"
        footer += f"{'=' * 60}"

    return header + "\n" + page_content + footer


@tool
def fetch_remote_logs(
    server: str,
    service: str = None,
    lines: int = 1000,
    since: str = None,
    priority: str = None
) -> str:
    """Fetch recent log entries from a remote server via SSH using journalctl.

    Args:
        server: SSH server name (e.g., 'zeus' or 'hera')
        service: Systemd service name to filter logs (e.g., 'apache2', 'postfix', 'dovecot')
        lines: Number of recent lines to fetch (default: 1000)
        since: Time range for logs (e.g., '1 hour ago', '2 days ago', 'today')
        priority: Log priority filter (e.g., 'err', 'warning', 'info')
    """
    try:
        # Whitelist allowed servers
        ALLOWED_SERVERS = ['zeus', 'hera']
        if server not in ALLOWED_SERVERS:
            return f"Error: Server must be one of {ALLOWED_SERVERS}"

        # Validate lines parameter
        if not isinstance(lines, int) or lines < 1 or lines > 10000:
            return "Error: lines must be an integer between 1 and 10000"

        # Whitelist allowed priorities
        ALLOWED_PRIORITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
        if priority and priority not in ALLOWED_PRIORITIES:
            return f"Error: priority must be one of {ALLOWED_PRIORITIES}"

        # Validate service name (alphanumeric, dash, underscore, dot only)
        if service:
            if not re.match(r'^[a-zA-Z0-9._-]+$', service):
                return "Error: service name contains invalid characters"

        # Build journalctl command parts as list for safe execution
        # Add sudo since debian user needs elevated privileges
        journalctl_parts = ['sudo', 'journalctl', '-n', str(lines)]

        if service:
            journalctl_parts.extend(['-u', service])

        if since:
            # Validate since parameter against common patterns
            # Allow simple time expressions only
            if not re.match(r'^(\d+\s+(second|minute|hour|day|week|month|year)s?\s+ago|today|yesterday|\d{4}-\d{2}-\d{2})$', since):
                return "Error: 'since' parameter must be in format like '1 hour ago', 'today', 'yesterday', or 'YYYY-MM-DD'"
            journalctl_parts.extend(['--since', since])

        if priority:
            journalctl_parts.extend(['--priority', priority])

        # Build safe SSH command using shlex.quote for the entire journalctl command
        journalctl_cmd = ' '.join(shlex.quote(part) for part in journalctl_parts)

        # Execute via SSH using list form to avoid shell injection
        result = subprocess.run(
            ['ssh', server, journalctl_cmd],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            service_info = f" from service '{service}'" if service else ""
            since_info = f" since '{since}'" if since else ""
            priority_info = f" (priority: {priority})" if priority else ""
            output = f"Successfully fetched {lines} lines from {server}{service_info}{since_info}{priority_info}:\n{result.stdout}"
            # Paginate if too large
            return paginate_output(output, max_tokens_per_page=6000, tool_name="fetch_remote_logs")
        else:
            return f"Error fetching logs from {server}: {result.stderr}"
    except subprocess.TimeoutExpired:
        return f"Error: SSH connection to {server} timed out"
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def analyze_log_patterns(log_text: str, log_type: str = "apache") -> str:
    """Analyze log entries for patterns and statistics.

    Args:
        log_text: Raw log entries to analyze
        log_type: Type of log (apache, nginx, postfix, dovecot)
    """
    lines = log_text.strip().split('\n')

    # Basic statistics
    stats = {
        'total_lines': len(lines),
        'ip_addresses': Counter(),
        'status_codes': Counter(),
        'user_agents': Counter(),
        'request_paths': Counter(),
        'request_methods': Counter(),
        'timestamps': [],
        'suspicious_patterns': []
    }

    # Parse based on log type
    if log_type in ['apache', 'nginx']:
        # Apache/Nginx combined log format
        apache_pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \S+ "([^"]*)" "([^"]*)"'

        for line in lines:
            match = re.search(apache_pattern, line)
            if match:
                ip, timestamp, method, path, status, referer, ua = match.groups()
                stats['ip_addresses'][ip] += 1
                stats['status_codes'][status] += 1
                stats['request_methods'][method] += 1
                stats['request_paths'][path] += 1
                stats['user_agents'][ua] += 1

                # Detect suspicious patterns
                if status in ['401', '403', '404']:
                    stats['suspicious_patterns'].append(f"Auth/Not found: {ip} -> {path}")
                if 'admin' in path.lower() or 'wp-' in path.lower():
                    stats['suspicious_patterns'].append(f"Admin/WP probe: {ip} -> {path}")
                if method in ['POST', 'PUT', 'DELETE'] and status == '200':
                    stats['suspicious_patterns'].append(f"Successful modification: {ip} {method} {path}")

    elif log_type in ['postfix', 'dovecot']:
        # Mail server logs
        for line in lines:
            # Extract IPs from mail logs
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', line)
            if ip_match:
                ip = ip_match.group(1)
                stats['ip_addresses'][ip] += 1

            # Detect authentication failures
            if 'authentication failed' in line.lower() or 'failed' in line.lower():
                stats['suspicious_patterns'].append(f"Auth failure: {line[:100]}")

            # Detect relay attempts
            if 'relay' in line.lower() and 'denied' in line.lower():
                stats['suspicious_patterns'].append(f"Relay attempt: {line[:100]}")

    # Format output
    output = f"=== Log Analysis Results ===\n"
    output += f"Total lines analyzed: {stats['total_lines']}\n\n"

    output += f"Top 10 IP addresses:\n"
    for ip, count in stats['ip_addresses'].most_common(10):
        output += f"  {ip}: {count} requests\n"

    if stats['status_codes']:
        output += f"\nHTTP Status codes:\n"
        for code, count in stats['status_codes'].most_common():
            output += f"  {code}: {count}\n"

    if stats['request_methods']:
        output += f"\nRequest methods:\n"
        for method, count in stats['request_methods'].most_common():
            output += f"  {method}: {count}\n"

    if stats['suspicious_patterns']:
        output += f"\nSuspicious patterns detected ({len(stats['suspicious_patterns'])} total):\n"
        for pattern in stats['suspicious_patterns'][:20]:  # Show first 20
            output += f"  • {pattern}\n"

    # Paginate if too large
    return paginate_output(output, max_tokens_per_page=6000, tool_name="analyze_log_patterns")


@tool
def detect_anomalies(log_text: str, threshold: float = 3.0) -> str:
    """Detect statistical anomalies in log patterns.

    Args:
        log_text: Raw log entries
        threshold: Standard deviation threshold for anomaly detection (default: 3.0)
    """
    lines = log_text.strip().split('\n')

    # Time-based analysis
    hourly_requests = defaultdict(int)
    ip_request_sizes = defaultdict(list)

    for line in lines:
        # Extract timestamp if available
        timestamp_match = re.search(r'\[([^\]]+)\]', line)
        if timestamp_match:
            try:
                # Parse timestamp (Apache format)
                ts_str = timestamp_match.group(1)
                # Extract hour
                hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', ts_str)
                if hour_match:
                    hour = hour_match.group(1)
                    hourly_requests[hour] += 1
            except:
                pass

        # Extract IP and count requests per IP
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            ip = ip_match.group(1)
            ip_request_sizes[ip].append(len(line))

    output = "=== Anomaly Detection Results ===\n\n"

    # Analyze hourly distribution
    if hourly_requests:
        import statistics
        counts = list(hourly_requests.values())
        if len(counts) > 1:
            mean = statistics.mean(counts)
            stdev = statistics.stdev(counts)

            output += f"Hourly request distribution:\n"
            output += f"  Mean: {mean:.1f}, StdDev: {stdev:.1f}\n"

            anomalous_hours = []
            for hour, count in sorted(hourly_requests.items()):
                z_score = (count - mean) / stdev if stdev > 0 else 0
                if abs(z_score) > threshold:
                    anomalous_hours.append((hour, count, z_score))

            if anomalous_hours:
                output += f"\n  Anomalous hours (z-score > {threshold}):\n"
                for hour, count, z_score in anomalous_hours:
                    output += f"    Hour {hour}: {count} requests (z-score: {z_score:.2f})\n"

    # Analyze IPs with unusual behavior
    output += f"\nIPs with unusual request patterns:\n"
    for ip, sizes in sorted(ip_request_sizes.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        if len(sizes) > 10:  # Only analyze IPs with enough samples
            import statistics
            mean_size = statistics.mean(sizes)
            stdev_size = statistics.stdev(sizes) if len(sizes) > 1 else 0
            output += f"  {ip}: {len(sizes)} requests, avg size: {mean_size:.0f} bytes\n"

    # Paginate if too large
    return paginate_output(output, max_tokens_per_page=6000, tool_name="detect_anomalies")


@tool
def check_ip_reputation(ip_address: str) -> str:
    """Check if an IP address is known for malicious activity.

    Args:
        ip_address: IP address to check
    """
    # Check against common blacklist patterns
    suspicious = []

    # Check if it's a known scanner range
    if ip_address.startswith('185.'):
        suspicious.append("IP in range commonly used by scanners")

    # Check if it looks like a cloud provider (often used for attacks)
    aws_ranges = ['3.', '13.', '18.', '34.', '35.', '52.', '54.']
    if any(ip_address.startswith(r) for r in aws_ranges):
        suspicious.append("Appears to be AWS IP (check if legitimate)")

    # Would integrate with real reputation APIs in production
    # e.g., AbuseIPDB, Project Honeypot, etc.

    if suspicious:
        return f"IP {ip_address} has suspicious indicators:\n" + "\n".join(f"  • {s}" for s in suspicious)
    else:
        return f"IP {ip_address}: No immediate red flags (manual verification recommended)"


@tool
def generate_fail2ban_rule(pattern_description: str, log_examples: str) -> str:
    """Generate a fail2ban filter rule based on attack patterns.

    Args:
        pattern_description: Description of the attack pattern
        log_examples: Example log lines showing the pattern
    """
    output = f"=== Suggested fail2ban Filter ===\n\n"
    output += f"Pattern: {pattern_description}\n\n"
    output += f"# Add to /etc/fail2ban/filter.d/custom-attack.conf\n"
    output += f"[Definition]\n"
    output += f"# {pattern_description}\n"

    # Try to extract common patterns from examples
    lines = log_examples.strip().split('\n')[:5]
    output += f"\nExample log lines:\n"
    for line in lines:
        output += f"# {line[:80]}...\n"

    output += f"\nfailregex = ^.*your_pattern_here.*<HOST>.*$\n"
    output += f"ignoreregex =\n\n"
    output += f"# Then add to /etc/fail2ban/jail.local:\n"
    output += f"# [custom-attack]\n"
    output += f"# enabled = true\n"
    output += f"# port = http,https\n"
    output += f"# filter = custom-attack\n"
    output += f"# logpath = /var/log/apache2/access.log\n"
    output += f"# maxretry = 3\n"
    output += f"# bantime = 3600\n"

    return output


@tool
def save_analysis_report(content: str, filename: str = None) -> str:
    """Save analysis results to a file.

    Args:
        content: Report content to save
        filename: Output filename (auto-generated if not provided)
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"log_analysis_{timestamp}.txt"

    try:
        filepath = os.path.join(os.path.expanduser("~"), filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return f"Report saved to: {filepath}"
    except Exception as e:
        return f"Error saving report: {str(e)}"


@tool
def aggregate_logs(log_text: str, method: str = "sample") -> str:
    """Aggregate large log datasets to fit within context limits.

    IMPORTANT: Use this tool FIRST when dealing with large log outputs (>500 lines)
    to reduce data size before analysis.

    Args:
        log_text: Raw log text to aggregate
        method: Aggregation method - 'sample', 'errors_only', 'unique_ips', or 'time_windows'
    """
    lines = log_text.strip().split('\n')
    total_lines = len(lines)

    # Estimate tokens
    tokens = estimate_tokens(log_text)

    output = f"=== Log Aggregation Report ===\n"
    output += f"Original: {total_lines} lines (~{tokens} tokens)\n"
    output += f"Method: {method}\n\n"

    if method == "sample":
        # Intelligent sampling: keep first 100, last 100, and random middle samples
        if total_lines <= 500:
            aggregated = lines
            output += "Dataset small enough, no sampling needed.\n\n"
        else:
            sample_size = min(300, total_lines)
            first_chunk = lines[:100]
            last_chunk = lines[-100:]

            # Sample middle section
            import random
            middle_section = lines[100:-100]
            middle_sample = random.sample(middle_section, min(100, len(middle_section))) if middle_section else []

            aggregated = first_chunk + middle_sample + last_chunk
            output += f"Sampled to {len(aggregated)} lines (first 100, random middle 100, last 100)\n\n"

    elif method == "errors_only":
        # Keep only error/warning/critical entries
        error_keywords = ['error', 'fail', 'denied', 'reject', 'critical', 'alert', 'warning', '401', '403', '404', '500', '502', '503']
        aggregated = [line for line in lines if any(keyword in line.lower() for keyword in error_keywords)]
        output += f"Filtered to {len(aggregated)} error/warning lines\n\n"

    elif method == "unique_ips":
        # Extract unique IP patterns and their representative lines
        ip_examples = {}
        for line in lines:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                if ip not in ip_examples:
                    ip_examples[ip] = line

        aggregated = list(ip_examples.values())
        output += f"Reduced to {len(aggregated)} unique IPs (one example per IP)\n\n"

    elif method == "time_windows":
        # Group by time windows and keep representatives
        time_buckets = defaultdict(list)
        for line in lines:
            # Extract hour from timestamp if present
            hour_match = re.search(r'(\d{2}):\d{2}:\d{2}', line)
            if hour_match:
                hour = hour_match.group(1)
                time_buckets[hour].append(line)
            else:
                time_buckets['unknown'].append(line)

        # Keep max 10 samples per time window
        aggregated = []
        for hour, hour_lines in sorted(time_buckets.items()):
            sample_count = min(10, len(hour_lines))
            aggregated.extend(hour_lines[:sample_count])

        output += f"Grouped by time windows, sampled to {len(aggregated)} lines\n\n"

    else:
        return f"Error: Unknown aggregation method '{method}'. Use: sample, errors_only, unique_ips, or time_windows"

    # Build result
    aggregated_text = '\n'.join(aggregated)
    new_tokens = estimate_tokens(aggregated_text)
    output += f"Aggregated result: {len(aggregated)} lines (~{new_tokens} tokens)\n"
    output += f"Reduction: {100 * (1 - new_tokens/tokens):.1f}%\n\n"
    output += "=" * 50 + "\n"
    output += aggregated_text

    # Paginate if still too large after aggregation
    return paginate_output(output, max_tokens_per_page=6000, tool_name="aggregate_logs")


@tool
def create_log_summary(log_text: str) -> str:
    """Create a statistical summary of logs without including raw log lines.

    IMPORTANT: Use this for initial overview of very large datasets (>1000 lines)
    before doing detailed analysis.

    Args:
        log_text: Raw log text to summarize
    """
    lines = log_text.strip().split('\n')
    total_lines = len(lines)
    tokens = estimate_tokens(log_text)

    summary = f"=== Log Statistical Summary ===\n"
    summary += f"Dataset size: {total_lines} lines (~{tokens} tokens)\n\n"

    # Extract and count IPs
    ip_counter = Counter()
    status_codes = Counter()
    methods = Counter()
    error_count = 0
    unique_patterns = set()

    for line in lines:
        # Count IPs
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if ip_match:
            ip_counter[ip_match.group(1)] += 1

        # Count HTTP status codes
        status_match = re.search(r'" (\d{3}) ', line)
        if status_match:
            status_codes[status_match.group(1)] += 1

        # Count HTTP methods
        method_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ', line)
        if method_match:
            methods[method_match.group(1)] += 1

        # Count errors
        if any(err in line.lower() for err in ['error', 'fail', 'denied', 'reject', '40', '50']):
            error_count += 1

        # Collect unique path patterns (simplified)
        path_match = re.search(r'"(?:GET|POST|PUT|DELETE) ([^ ]+) ', line)
        if path_match:
            unique_patterns.add(path_match.group(1))

    # Build summary
    summary += f"📊 Key Statistics:\n"
    summary += f"  • Unique IPs: {len(ip_counter)}\n"
    summary += f"  • Unique paths/patterns: {len(unique_patterns)}\n"
    summary += f"  • Lines with errors/warnings: {error_count} ({100*error_count/total_lines:.1f}%)\n\n"

    summary += f"🔝 Top 10 IPs:\n"
    for ip, count in ip_counter.most_common(10):
        percentage = 100 * count / total_lines
        summary += f"  {ip:15s}: {count:5d} requests ({percentage:5.1f}%)\n"

    if status_codes:
        summary += f"\n📈 HTTP Status Codes:\n"
        for code, count in sorted(status_codes.items()):
            percentage = 100 * count / total_lines
            summary += f"  {code}: {count:5d} ({percentage:5.1f}%)\n"

    if methods:
        summary += f"\n🔧 HTTP Methods:\n"
        for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
            percentage = 100 * count / total_lines
            summary += f"  {method:7s}: {count:5d} ({percentage:5.1f}%)\n"

    summary += f"\n💡 Recommendation:\n"
    if tokens > 8000:
        summary += f"  ⚠️  Dataset is large ({tokens} tokens). Use 'aggregate_logs' tool\n"
        summary += f"      with method='errors_only' or 'sample' before detailed analysis.\n"
    else:
        summary += f"  ✓ Dataset size is manageable for direct analysis.\n"

    return summary


# ============================================================================
# AGENT LOGIC
# ============================================================================

def run_log_analysis_agent(llm_with_tools, user_input: str, message_history: list = None):
    """Run the log analysis agent"""
    if message_history is None:
        message_history = []

    message_history.append(HumanMessage(content=user_input))

    for iteration in range(15):  # Allow more iterations for complex analysis
        response = llm_with_tools.invoke(message_history)
        message_history.append(response)

        if hasattr(response, 'tool_calls') and response.tool_calls:
            print(f"\n🔧 Agent is working...")

            for tool_call in response.tool_calls:
                tool_name = tool_call['name']
                tool_args = tool_call['args']

                print(f"   → {tool_name}({json.dumps(tool_args, indent=2) if len(str(tool_args)) < 50 else tool_name})")

                tool_result = execute_tool_call(tool_name, tool_args)

                message_history.append(ToolMessage(
                    content=str(tool_result),
                    tool_call_id=tool_call['id']
                ))

            continue

        if hasattr(response, 'content'):
            return response.content, message_history
        else:
            return str(response), message_history

    return "Analysis complete (max iterations reached)", message_history


def execute_tool_call(tool_name: str, args: dict):
    """Execute a tool by name"""
    tool_map = {
        'get_more_data': get_more_data,
        'fetch_remote_logs': fetch_remote_logs,
        'create_log_summary': create_log_summary,
        'aggregate_logs': aggregate_logs,
        'analyze_log_patterns': analyze_log_patterns,
        'detect_anomalies': detect_anomalies,
        'check_ip_reputation': check_ip_reputation,
        'generate_fail2ban_rule': generate_fail2ban_rule,
        'save_analysis_report': save_analysis_report
    }

    if tool_name not in tool_map:
        return f"Error: Unknown tool '{tool_name}'"

    try:
        tool_func = tool_map[tool_name]
        result = tool_func.invoke(args)
        return result
    except Exception as e:
        import traceback
        return f"Error executing {tool_name}: {str(e)}\n{traceback.format_exc()}"


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    print("=" * 70)
    print("AI-Powered Log Analysis Agent")
    print("Detecting unusual patterns beyond fail2ban regex")
    print("Using journalctl on zeus and hera servers")
    print("=" * 70)

    # Initialize LLM
    models_to_try = ["qwen3:14b", "llama3.1:70b", "llama3.1:8b", "qwen2.5:32b"]

    llm = None
    for model in models_to_try:
        try:
            print(f"Loading model: {model}...", end=" ")
            llm = ChatOllama(
                model=model,
                temperature=0,
                base_url="http://localhost:11434"
            )
            llm.invoke("test")
            print("✓")
            break
        except:
            print("✗")

    if llm is None:
        print("\n❌ Could not connect to Ollama. Make sure it's running.")
        return

    # Bind tools
    tools = [
        get_more_data,
        fetch_remote_logs,
        create_log_summary,
        aggregate_logs,
        analyze_log_patterns,
        detect_anomalies,
        check_ip_reputation,
        generate_fail2ban_rule,
        save_analysis_report
    ]

    llm_with_tools = llm.bind_tools(tools)

    print("\n✓ Agent ready!")
    print("\nAvailable tools:")
    for tool in tools:
        print(f"  • {tool.name}")

    print("\n" + "=" * 70)
    print("Example commands:")
    print("  • Analyze apache2 logs from zeus for the last 1000 lines")
    print("  • Check logs from hera for brute force attempts on postfix service")
    print("  • Fetch error-level logs from zeus since 1 hour ago")
    print("  • Look for unusual patterns in dovecot logs from both servers")
    print("  • Generate a fail2ban rule for the suspicious activity you found")
    print("\nType 'exit' to quit, 'clear' to clear history")
    print("=" * 70)

    system_message = SystemMessage(content="""You are an expert security analyst specializing in log analysis.
Your job is to:
1. Fetch and analyze server logs using journalctl from zeus and hera servers
2. Identify unusual patterns that regex-based tools like fail2ban might miss
3. Detect sophisticated attacks: slow scans, credential stuffing, application-layer attacks
4. Provide actionable insights and suggest fail2ban rules
5. Look for: unusual user agents, timing patterns, target sequences, geo-anomalies

Available servers: zeus, hera (redundant nodes)
Common services: apache2, nginx, postfix, dovecot, sshd

⚠️ PAGINATION SYSTEM (CRITICAL):
You have a 32k context window. Tool outputs larger than 6000 tokens are automatically PAGINATED (not truncated).

When you see "PAGINATED OUTPUT (Page 1 of N)":
- You received only the FIRST PAGE of the data
- There is MORE DATA available on subsequent pages
- Use get_more_data(data_id='...', page=2) to get the next page
- Continue calling get_more_data with incrementing page numbers to see all data
- The pagination message shows the data_id and total number of pages

IMPORTANT: When you see paginated output, you MUST use get_more_data to retrieve additional pages if you need complete information. Don't assume page 1 contains everything!

⚠️ CONTEXT WINDOW MANAGEMENT:
For very large log datasets, use this multi-layered approach:

1. When fetching logs (especially >500 lines):
   - First use 'create_log_summary' to get statistical overview
   - This shows IP distribution, error rates, status codes WITHOUT raw logs

2. For detailed analysis of large datasets:
   - Use 'aggregate_logs' to reduce data size BEFORE 'analyze_log_patterns'
   - Methods: 'errors_only' (security focus), 'sample' (balanced), 'unique_ips', 'time_windows'

3. For targeted investigation:
   - Fetch smaller, filtered datasets using journalctl options
   - Use 'since' for time ranges (e.g., '1 hour ago')
   - Use 'priority' for error-level logs only
   - Reduce 'lines' parameter (default 1000 → try 200-500)

4. If tool output is paginated:
   - Use get_more_data to retrieve all pages
   - Example: get_more_data(data_id='abc123', page=2)

Example workflow for large dataset:
  User: "Analyze apache2 logs from zeus"
  1. fetch_remote_logs(server='zeus', service='apache2', lines=1000)
  2. If paginated, use get_more_data to retrieve all pages
  3. create_log_summary(log_text=<result>) ← Get overview first
  4. aggregate_logs(log_text=<result>, method='errors_only') ← Reduce size
  5. analyze_log_patterns(log_text=<aggregated>) ← Detailed analysis

Be thorough and explain your findings clearly.""")

    message_history = [system_message]

    while True:
        try:
            user_input = input("\n🧑 You: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit", "q"]:
                print("\nGoodbye!")
                break

            if user_input.lower() == "clear":
                message_history = [system_message]
                print("History cleared!")
                continue

            print("\n🤖 Agent:", end=" ", flush=True)
            response, message_history = run_log_analysis_agent(
                llm_with_tools, user_input, message_history
            )
            print(response)

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
