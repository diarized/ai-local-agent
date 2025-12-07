#!/usr/bin/env python3

"""
Local AI Agent with Tool Use
Compatible with LangChain 1.0+
Executes local commands and provides information retrieval
"""

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
import subprocess
import os
import json
import hashlib
import time

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
def web_search(query: str) -> str:
    """Search the web using DuckDuckGo for current information.

    Args:
        query: The search query string
    """
    try:
        import ddgs
        results = ddgs.DDGS().text(query, max_results=5)
        output = "\n".join([f"• {r['title']}: {r['body']}" for r in results])
        # Truncate if too large (unlikely with 5 results, but safety check)
        return paginate_output(output, max_tokens_per_page=6000, tool_name="web_search")
    except ImportError:
        return "Error: duckduckgo-search not installed. Run: pip install duckduckgo-search"
    except Exception as e:
        return f"Search error: {str(e)}"


@tool
def run_shell_command(command: str) -> str:
    """Execute a shell command (blacklist-based security with injection protection).

    Blocked: destructive operations (rm, dd), system modification (shutdown, sudo),
    network changes (iptables, ifconfig), package management (apt, pip),
    code execution (python, bash), file downloads (wget, curl), and other risky operations.

    Also blocks shell injection via metacharacters (;, &&, ||, |, `, $(), etc.)

    Args:
        command: The shell command to execute
    """
    import re

    # Comprehensive blacklist of dangerous commands
    blacklisted_commands = [
        # Destructive file operations
        'rm', 'rmdir', 'shred', 'dd', 'mkfs', 'fdisk', 'parted', 'gdisk',
        'wipefs', 'sgdisk', 'cfdisk', 'sfdisk',

        # System modification and power
        'shutdown', 'reboot', 'halt', 'poweroff', 'init', 'telinit',
        'systemctl', 'service', 'systemd', 'initctl',

        # Process control
        'kill', 'killall', 'pkill', 'killall5', 'skill',

        # Permission and ownership changes
        'chmod', 'chown', 'chgrp', 'chattr', 'setfacl',

        # User and group management
        'useradd', 'userdel', 'usermod', 'adduser', 'deluser',
        'groupadd', 'groupdel', 'groupmod', 'addgroup', 'delgroup',
        'passwd', 'chpasswd', 'gpasswd',

        # Privilege escalation
        'sudo', 'su', 'visudo', 'sudoedit', 'pkexec',

        # Network manipulation
        'iptables', 'ip6tables', 'nft', 'nftables', 'ip', 'ifconfig',
        'route', 'tc', 'ethtool', 'iwconfig',

        # Network tools (potentially dangerous)
        'nc', 'netcat', 'ncat', 'socat', 'nmap', 'zenmap',
        'tcpdump', 'wireshark', 'tshark', 'ettercap',

        # Package management
        'apt', 'apt-get', 'aptitude', 'dpkg', 'dpkg-reconfigure',
        'yum', 'dnf', 'rpm', 'zypper',
        'pacman', 'makepkg', 'yay', 'paru',
        'snap', 'flatpak', 'appimage',
        'pip', 'pip3', 'easy_install',
        'npm', 'yarn', 'pnpm', 'gem', 'cargo',

        # Compilers and interpreters
        'gcc', 'g++', 'clang', 'clang++', 'cc', 'c++',
        'make', 'cmake', 'ninja', 'meson',
        'python', 'python2', 'python3', 'pypy',
        'perl', 'ruby', 'irb', 'node', 'nodejs', 'deno', 'bun',
        'php', 'java', 'javac', 'scala', 'kotlin',
        'go', 'rust', 'rustc',
        'bash', 'sh', 'zsh', 'fish', 'ksh', 'csh', 'tcsh', 'dash',
        'exec', 'eval', 'source',

        # File download and transfer
        'wget', 'curl', 'aria2c', 'axel',
        'scp', 'sftp', 'ftp', 'lftp', 'ncftp',
        'rsync', 'rclone',
        'git', 'svn', 'hg', 'cvs',

        # Container and virtualization
        'docker', 'podman', 'containerd', 'runc',
        'kubectl', 'k3s', 'minikube',
        'vagrant', 'vboxmanage', 'virsh', 'virt-manager',
        'qemu', 'kvm', 'lxc', 'lxd',

        # Database clients
        'mysql', 'mariadb', 'psql', 'postgres', 'postgresql',
        'mongo', 'mongod', 'redis-cli', 'sqlite', 'sqlite3',

        # Filesystem operations
        'mount', 'umount', 'mountpoint', 'findmnt',
        'cryptsetup', 'luks', 'dmsetup',
        'mkswap', 'swapon', 'swapoff',
        'fsck', 'e2fsck', 'xfs_repair',
        'resize2fs', 'xfs_growfs',

        # Scheduled execution
        'crontab', 'at', 'batch', 'anacron',

        # Terminal multiplexers and background execution
        'screen', 'tmux', 'nohup', 'disown',

        # System logging and auditing (could expose sensitive data)
        'journalctl', 'dmesg', 'ausearch', 'aureport',

        # Text editors (could modify system files)
        'vi', 'vim', 'nvim', 'nano', 'emacs', 'ed', 'ex',

        # Messaging and notifications
        'write', 'wall', 'mesg', 'talk',

        # Shell built-ins and control
        'alias', 'unalias', 'export', 'unset', 'set',
        'trap', 'ulimit', 'umask',

        # Archive extraction (could extract malicious files)
        'tar', 'untar', 'unzip', 'gunzip', 'bunzip2', 'unxz',
        '7z', 'rar', 'unrar',

        # System configuration tools
        'sysctl', 'modprobe', 'insmod', 'rmmod', 'lsmod',
        'update-grub', 'grub-install', 'grub-mkconfig',
        'update-initramfs', 'dracut',

        # Disk and partition tools
        'losetup', 'partprobe', 'blkid', 'blockdev',

        # SELinux/AppArmor
        'setenforce', 'setsebool', 'chcon', 'restorecon',
        'aa-enforce', 'aa-complain', 'aa-disable',

        # Other potentially dangerous
        'chroot', 'fakeroot', 'fakechroot',
        'strace', 'ltrace', 'gdb', 'lldb',
        'objdump', 'readelf', 'strings',
    ]

    cmd_parts = command.strip().split()

    if not cmd_parts:
        return "Error: Empty command"

    # Extract base command (handle paths like /bin/ls or ./script)
    base_command = os.path.basename(cmd_parts[0])

    # Check if base command is blacklisted
    if base_command in blacklisted_commands:
        return (f"Error: Command '{base_command}' is blacklisted for security reasons.\n"
                f"Blocked categories: destructive operations, system modification, "
                f"network changes, package management, code execution, file downloads, "
                f"and other risky operations.")

    # CRITICAL: Check for newline and null byte injection
    if '\n' in command or '\r' in command or '\x00' in command:
        return ("Error: Command contains illegal characters (newlines or null bytes).\n"
                "This is blocked to prevent command injection attacks.")

    # Check for shell injection metacharacters
    # Allow single pipe for simple piping, but block dangerous patterns
    dangerous_patterns = [
        r';',           # Command chaining
        r'&&',          # AND chaining
        r'\|\|',        # OR chaining
        r'`',           # Command substitution (backticks)
        r'\$\(',        # Command substitution $(...)
        r'\$[A-Za-z_]', # Variable expansion
        r'\$\{[A-Za-z_]',  # Brace variable expansion
        r'\{.*,.*\}',   # Brace expansion
        r'>\s*/dev/',   # Writing to devices
        r'<\s*/dev/',   # Reading from devices
        r'>\s*/proc/',  # Writing to proc
        r'>\s*/sys/',   # Writing to sys
        r'\|.*\b(bash|sh|zsh|fish|python|perl|ruby|node)\b',  # Piping to interpreters
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, command):
            return (f"Error: Command contains potentially dangerous shell metacharacters or patterns.\n"
                    f"Detected pattern: {pattern}\n"
                    f"This is blocked to prevent command injection attacks.")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.expanduser("~")
        )

        output = f"=== Command: {command} ===\n"
        output += f"Exit code: {result.returncode}\n"

        if result.stdout:
            output += f"\nOutput:\n{result.stdout}"
        if result.stderr:
            output += f"\nErrors:\n{result.stderr}"

        # Paginate if too large
        return paginate_output(output, max_tokens_per_page=6000, tool_name="run_shell_command")
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds"
    except Exception as e:
        return f"Error executing command: {str(e)}"


@tool
def search_files(pattern: str, directory: str = "~") -> str:
    """Search for files containing a text pattern using grep.

    Args:
        pattern: The text pattern to search for
        directory: Directory to search in (default: home directory)
    """
    try:
        expanded_dir = os.path.expanduser(directory)
        if not os.path.exists(expanded_dir):
            return f"Error: Directory {directory} does not exist"

        result = subprocess.run(
            ["grep", "-r", "-l", "--include=*.txt", "--include=*.py", "--include=*.md",
             pattern, expanded_dir],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            files = result.stdout.strip().split('\n')
            output = f"=== Files containing '{pattern}' ===\n"
            output += f"Found {len(files)} file(s)\n\n"
            output += result.stdout
            # Paginate if too large
            return paginate_output(output, max_tokens_per_page=6000, tool_name="search_files")
        elif result.returncode == 1:
            return f"No files found containing '{pattern}'"
        else:
            return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds"
    except Exception as e:
        return f"Error searching files: {str(e)}"


@tool
def find_files(filename_pattern: str, directory: str = "~") -> str:
    """Find files by name pattern using find command.

    Args:
        filename_pattern: The filename pattern to search for (e.g., "*.py")
        directory: Directory to search in (default: home directory)
    """
    try:
        expanded_dir = os.path.expanduser(directory)
        if not os.path.exists(expanded_dir):
            return f"Error: Directory {directory} does not exist"

        result = subprocess.run(
            ["find", expanded_dir, "-name", filename_pattern, "-type", "f"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.stdout:
            files = result.stdout.strip().split('\n')
            output = f"=== Files matching '{filename_pattern}' ===\n"

            if len(files) > 50:
                output += f"Found {len(files)} files (showing first 50)\n\n"
                output += '\n'.join(files[:50])
            else:
                output += f"Found {len(files)} file(s)\n\n"
                output += result.stdout

            # Paginate if too large
            return paginate_output(output, max_tokens_per_page=6000, tool_name="find_files")
        else:
            return f"No files found matching '{filename_pattern}'"
    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds"
    except Exception as e:
        return f"Error finding files: {str(e)}"


@tool
def read_file(filepath: str, lines: int = None) -> str:
    """Read contents of a file.

    Args:
        filepath: Path to the file to read
        lines: Optional number of lines to read (default: entire file)
    """
    try:
        expanded_path = os.path.expanduser(filepath)

        if not os.path.exists(expanded_path):
            return f"Error: File '{filepath}' does not exist"

        if not os.path.isfile(expanded_path):
            return f"Error: '{filepath}' is not a file"

        # Check file size
        file_size = os.path.getsize(expanded_path)
        if file_size > 1024 * 1024:  # 1MB
            return f"Error: File is too large ({file_size / 1024:.1f} KB). Use 'head' or 'tail' command instead."

        with open(expanded_path, 'r') as f:
            if lines:
                content = ''.join(f.readlines()[:lines])
            else:
                content = f.read()

        output = f"=== File: {filepath} ===\n"
        output += f"Size: {file_size} bytes\n\n"
        output += content

        # Paginate if too large (token-wise)
        return paginate_output(output, max_tokens_per_page=6000, tool_name="read_file")
    except UnicodeDecodeError:
        return f"Error: File '{filepath}' appears to be binary"
    except PermissionError:
        return f"Error: Permission denied to read '{filepath}'"
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tool
def get_system_info() -> str:
    """Get system information (OS, CPU, memory, disk usage)."""
    try:
        info = "=== System Information ===\n\n"

        # OS info
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
        info += f"OS: {result.stdout}\n"

        # CPU info
        result = subprocess.run(['nproc'], capture_output=True, text=True, timeout=5)
        info += f"CPU cores: {result.stdout.strip()}\n"

        # Memory info
        result = subprocess.run(['free', '-h'], capture_output=True, text=True, timeout=5)
        info += f"\nMemory:\n{result.stdout}\n"

        # Disk usage
        result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
        info += f"Disk usage:\n{result.stdout}\n"

        # Uptime
        result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
        info += f"Uptime: {result.stdout}"

        # Paginate if too large (unlikely for system info, but safety check)
        return paginate_output(info, max_tokens_per_page=6000, tool_name="get_system_info")
    except Exception as e:
        return f"Error getting system info: {str(e)}"


# ============================================================================
# AGENT LOGIC
# ============================================================================

def run_agent_loop(llm_with_tools, user_input: str, message_history: list = None):
    """Run the agent loop"""
    if message_history is None:
        message_history = []

    message_history.append(HumanMessage(content=user_input))

    for iteration in range(10):  # Max 10 iterations
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

    return "Task complete (max iterations reached)", message_history


def execute_tool_call(tool_name: str, args: dict):
    """Execute a tool by name"""
    tool_map = {
        'get_more_data': get_more_data,
        'web_search': web_search,
        'run_shell_command': run_shell_command,
        'search_files': search_files,
        'find_files': find_files,
        'read_file': read_file,
        'get_system_info': get_system_info
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
    print("Local AI Agent with Tool Use")
    print("LangChain 1.0+ with Ollama")
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
        print("Run: ollama serve")
        print("Pull a model: ollama pull qwen3:14b")
        return

    # Bind tools
    tools = [
        get_more_data,
        web_search,
        run_shell_command,
        search_files,
        find_files,
        read_file,
        get_system_info
    ]

    llm_with_tools = llm.bind_tools(tools)

    print("\n✓ Agent ready!")
    print("\nAvailable tools:")
    for tool in tools:
        print(f"  • {tool.name}")

    print("\n" + "=" * 70)
    print("Example commands:")
    print("  • What files are in my current directory?")
    print("  • Search for Python files containing 'def main'")
    print("  • Show me system information")
    print("  • Read the contents of config.txt")
    print("  • What's today's date and system uptime?")
    print("\nType 'exit' to quit, 'clear' to clear history")
    print("=" * 70)

    system_message = SystemMessage(content="""You are a helpful AI assistant with access to local system tools.

Your capabilities:
1. Execute shell commands (blacklist-based security - most commands allowed)
2. Search for files by name or content
3. Read file contents (text files only)
4. Get system information
5. Search the web for current information
6. Navigate paginated results from large outputs

⚠️ PAGINATION SYSTEM (IMPORTANT):
You have a 32k token context window. Tool outputs larger than 6000 tokens are automatically PAGINATED (not truncated).

When you see "PAGINATED OUTPUT (Page 1 of N)":
- You received only the FIRST PAGE of the data
- There is MORE DATA available on subsequent pages
- Use get_more_data(data_id='...', page=2) to get the next page
- Continue calling get_more_data with incrementing page numbers to see all data
- The pagination message shows the data_id and total number of pages

Example workflow:
1. You run: read_file("large_log.txt")
2. You receive: Page 1 of 5 with data_id='abc123'
3. To see page 2: get_more_data(data_id='abc123', page=2)
4. To see page 3: get_more_data(data_id='abc123', page=3)
5. Continue until you reach the last page

IMPORTANT: When you see paginated output, you MUST use get_more_data to retrieve additional pages if you need complete information. Don't assume page 1 contains everything!

When using tools:
- Use run_shell_command for shell commands (blacklist prevents: rm, sudo, shutdown, apt, python, wget, etc.)
- Use search_files to find files containing specific text
- Use find_files to locate files by name pattern
- Use read_file to view file contents (max 1MB, auto-paginated if large)
- Use get_system_info for system statistics
- Use web_search for online information
- Use get_more_data to retrieve additional pages from paginated results

Be helpful and explain what you're doing when using tools.""")

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
            response, message_history = run_agent_loop(
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
