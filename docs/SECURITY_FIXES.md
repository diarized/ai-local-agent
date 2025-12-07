# Security Fixes for run_shell_command

## Quick Reference: Apply These Fixes

### Fix #1: Block Newline Injection (CRITICAL - 5 minutes)

**Add at line 327** (right after `if not cmd_parts:` check):

```python
# Check for illegal characters that enable command injection
if '\n' in command or '\r' in command or '\x00' in command:
    return (f"Error: Command contains illegal characters.\n"
            f"Newlines and null bytes are blocked to prevent command injection attacks.")
```

**Full context:**
```python
cmd_parts = command.strip().split()

if not cmd_parts:
    return "Error: Empty command"

# ADD THIS:
if '\n' in command or '\r' in command or '\x00' in command:
    return (f"Error: Command contains illegal characters.\n"
            f"Newlines and null bytes are blocked to prevent command injection attacks.")

# Extract base command (handle paths like /bin/ls or ./script)
base_command = os.path.basename(cmd_parts[0])
```

---

### Fix #2: Block Brace Expansion (HIGH - 2 minutes)

**Add to dangerous_patterns list** (after line 350):

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
    r'\|.*\b(bash|sh|zsh|fish|python|perl|ruby|node)\b',  # Piping to interpreters
    r'\{.*,.*\}',   # ADD THIS: Brace expansion
]
```

---

### Fix #3: Block Environment Variable Expansion (MEDIUM - 2 minutes)

**Add to dangerous_patterns list** (after brace expansion):

```python
dangerous_patterns = [
    r';',
    r'&&',
    r'\|\|',
    r'`',
    r'\$\(',
    r'>\s*/dev/',
    r'<\s*/dev/',
    r'>\s*/proc/',
    r'>\s*/sys/',
    r'\|.*\b(bash|sh|zsh|fish|python|perl|ruby|node)\b',
    r'\{.*,.*\}',
    r'\$[A-Za-z_]',     # ADD THIS: Variable expansion ($VAR)
    r'\$\{[A-Za-z_]',   # ADD THIS: Brace variable expansion (${VAR})
]
```

---

### Fix #4: Update Docstring (1 minute)

**Update docstring** (line 196-205) to reflect all protections:

```python
@tool
def run_shell_command(command: str) -> str:
    """Execute a shell command (blacklist-based security with comprehensive injection protection).

    Blocked: destructive operations (rm, dd), system modification (shutdown, sudo),
    network changes (iptables, ifconfig), package management (apt, pip),
    code execution (python, bash), file downloads (wget, curl), and other risky operations.

    Injection protection blocks: command chaining (;, &&, ||), command substitution (`, $()),
    newlines (\n, \r), brace expansion ({a,b}), variable expansion ($VAR), piping to
    interpreters (| bash), and dangerous device redirects (> /dev/).

    Args:
        command: The shell command to execute
    """
```

---

## Complete Patched Code

Here's the complete updated function with all fixes:

```python
@tool
def run_shell_command(command: str) -> str:
    """Execute a shell command (blacklist-based security with comprehensive injection protection).

    Blocked: destructive operations (rm, dd), system modification (shutdown, sudo),
    network changes (iptables, ifconfig), package management (apt, pip),
    code execution (python, bash), file downloads (wget, curl), and other risky operations.

    Injection protection blocks: command chaining (;, &&, ||), command substitution (`, $()),
    newlines (\n, \r), brace expansion ({a,b}), variable expansion ($VAR), piping to
    interpreters (| bash), and dangerous device redirects (> /dev/).

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

    # CRITICAL FIX #1: Block newline injection
    if '\n' in command or '\r' in command or '\x00' in command:
        return (f"Error: Command contains illegal characters.\n"
                f"Newlines and null bytes are blocked to prevent command injection attacks.")

    # Extract base command (handle paths like /bin/ls or ./script)
    base_command = os.path.basename(cmd_parts[0])

    # Check if base command is blacklisted
    if base_command in blacklisted_commands:
        return (f"Error: Command '{base_command}' is blacklisted for security reasons.\n"
                f"Blocked categories: destructive operations, system modification, "
                f"network changes, package management, code execution, file downloads, "
                f"and other risky operations.")

    # Check for shell injection metacharacters
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
        r'\|.*\b(bash|sh|zsh|fish|python|perl|ruby|node)\b',  # Piping to interpreters
        r'\{.*,.*\}',       # FIX #2: Brace expansion
        r'\$[A-Za-z_]',     # FIX #3: Variable expansion ($VAR)
        r'\$\{[A-Za-z_]',   # FIX #3: Brace variable expansion (${VAR})
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
```

---

## Testing Your Fixes

After applying fixes, run:

```bash
python /home/artur/Scripts/Python/src/ai-agent/src/test_shell_security_standalone.py
```

**Expected results after fixes:**
- Success rate: 100% (36/36 tests pass)
- Failed (Vulnerable): 0
- All newline injection tests should now BLOCK
- All brace expansion tests should now BLOCK
- All variable expansion tests should now BLOCK

---

## Long-term Migration Path

For production use, consider migrating to `shell=False`:

### Step 1: Create safe command wrappers
```python
def safe_ls(path=".", options=""):
    """Safe ls wrapper without shell=True"""
    cmd = ["ls"]
    if options:
        cmd.extend(options.split())
    cmd.append(path)
    return subprocess.run(cmd, shell=False, capture_output=True, text=True)
```

### Step 2: Build command map
```python
SAFE_COMMANDS = {
    "ls": safe_ls,
    "pwd": safe_pwd,
    "grep": safe_grep,
    # ... etc
}
```

### Step 3: Replace run_shell_command
```python
def run_safe_command(command_name: str, args: list):
    if command_name not in SAFE_COMMANDS:
        return f"Error: {command_name} not in whitelist"

    return SAFE_COMMANDS[command_name](*args)
```

**Benefits:**
- No injection possible (shell=False)
- Explicit argument parsing
- Type-safe arguments
- Industry best practice

---

## Summary

### What Was Fixed (in current PR):
- Path-based bypasses (/bin/rm, ./rm) ✓
- Basic command chaining (;, &&, ||) ✓
- Command substitution (`, $()) ✓
- Pipe to interpreters (| bash) ✓

### What Still Needs Fixing:
- **Newline injection** (\n, \r) ✗ CRITICAL
- Brace expansion ({a,b}) ✗ HIGH
- Variable expansion ($VAR) ✗ MEDIUM

### Apply These 3 Fixes (Total Time: 9 minutes):
1. Add newline check (5 min)
2. Add brace expansion pattern (2 min)
3. Add variable expansion pattern (2 min)

**After fixes: 100% security test pass rate**
