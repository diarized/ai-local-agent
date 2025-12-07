# Troubleshooting Guide

Common issues and solutions for the AI agent project.

## Ollama Connection Issues

### "Could not connect to Ollama"

**Symptoms:**
- Error: "Could not connect to Ollama at http://localhost:11434"
- Agent fails to start
- Connection refused errors

**Solutions:**

1. **Verify Ollama is running:**
   ```bash
   curl http://localhost:11434/api/tags
   ```

   Expected: JSON response with model list

   If connection fails, start Ollama:
   ```bash
   ollama serve
   ```

2. **Check Ollama is on correct port:**
   ```bash
   ps aux | grep ollama
   netstat -tulpn | grep 11434
   ```

3. **Verify at least one model is installed:**
   ```bash
   ollama list
   ```

   If no models are installed:
   ```bash
   ollama pull llama3.1:8b
   ```

4. **Check firewall settings:**
   ```bash
   sudo ufw status
   # Ensure port 11434 is not blocked
   ```

### "Model not found"

**Symptoms:**
- Error listing specific model name
- Agent can't find any models from priority list

**Solutions:**

1. **Check which models are actually installed:**
   ```bash
   ollama list
   ```

2. **Install at least one model from the priority list:**
   ```bash
   # Priority order: qwen3:14b, llama3.1:70b, llama3.1:8b, qwen2.5:32b
   ollama pull llama3.1:8b
   ```

3. **Verify model name matches exactly:**
   - Use `ollama list` to see exact names
   - Models are case-sensitive
   - Some models have version tags (e.g., `llama3.1:8b-instruct`)

## Dependency Issues

### "Error: duckduckgo-search not installed"

**Symptoms:**
- ImportError when starting general agent
- web_search tool unavailable

**Solutions:**

```bash
# Activate virtual environment
source venv/bin/activate

# Install ddgs package
pip install ddgs

# Or install all dependencies
pip install -r requirements.txt
```

### "No module named 'langchain'"

**Symptoms:**
- ImportError for langchain, langchain_core, or langchain_ollama
- Agent fails to import

**Solutions:**

```bash
# Activate virtual environment
source venv/bin/activate

# Install all LangChain dependencies
pip install langchain langchain-ollama langchain-core

# Verify installation
python -c "import langchain; print(langchain.__version__)"
```

### Version compatibility issues

**Symptoms:**
- Deprecated function warnings
- Unexpected behavior with tool binding

**Solutions:**

```bash
# Update to latest compatible versions
pip install --upgrade langchain>=1.1.2 langchain-ollama>=1.0.0 langchain-core>=1.1.1

# Check versions
pip list | grep langchain
```

## Log Analyzer Issues

### SSH Timeout

**Symptoms:**
- "SSH connection timed out" when fetching logs
- Long delays before errors
- Cannot connect to zeus or hera

**Solutions:**

1. **Verify SSH access manually:**
   ```bash
   ssh user@zeus
   ssh user@hera
   ```

2. **Check SSH key authentication:**
   ```bash
   ssh -v user@zeus journalctl -n 10
   # Look for "Offering public key" messages
   ```

3. **Configure SSH keys if not set up:**
   ```bash
   ssh-keygen -t ed25519
   ssh-copy-id user@zeus
   ssh-copy-id user@hera
   ```

4. **Check firewall rules:**
   ```bash
   # On remote server
   sudo ufw status
   # Ensure SSH port (22) is open
   ```

5. **Increase timeout in fetch_remote_logs:**
   Edit `log_analyzer.py` and increase timeout parameter in SSH commands

6. **Verify journalctl access:**
   ```bash
   # User must be in systemd-journal group or have sudo access
   ssh user@zeus "journalctl -n 10"
   ```

### "Permission denied" on remote logs

**Symptoms:**
- Can SSH but can't read journalctl
- Error: "Failed to read journal: Permission denied"

**Solutions:**

```bash
# On remote server, add user to systemd-journal group
sudo usermod -a -G systemd-journal username

# Or configure sudo access for journalctl
# Add to /etc/sudoers.d/journalctl:
# username ALL=(ALL) NOPASSWD: /usr/bin/journalctl
```

### Large log datasets cause context overflow

**Symptoms:**
- Agent seems slow or unresponsive
- Incomplete analysis of logs
- Memory warnings

**Solutions:**

1. **Use time filters:**
   ```
   Fetch logs from last 1 hour instead of all logs
   Analyze apache2 logs from zeus since 6 hours ago
   ```

2. **Let the agent aggregate:**
   - The agent should automatically use create_log_summary and aggregate_logs
   - If not, explicitly request: "Create a summary first, then analyze"

3. **Use specific filters:**
   ```
   Show only error logs (status codes 400+)
   Filter to authentication failures only
   ```

## General Agent Issues

### Shell commands fail with "command is blacklisted" or "dangerous metacharacters"

**Symptoms:**
- Error: "Command 'X' is blacklisted for security reasons"
- Error: "Command contains potentially dangerous shell metacharacters"
- run_shell_command rejects dangerous commands or injection attempts

**Solutions:**

The tool uses two layers of security:

**1. Command blacklist** - Blocks dangerous base commands:
- Destructive operations (rm, dd, shred, mkfs)
- System modification (shutdown, reboot, sudo, chmod)
- Network changes (iptables, ip, ifconfig)
- Package management (apt, pip, npm, yum, cargo)
- Code execution (python, bash, gcc, perl, node)
- File downloads (wget, curl, git, rsync)
- Database clients (mysql, psql, mongo)
- Text editors (vim, nano, emacs)
- Other risky operations (mount, crontab, docker)

**2. Injection protection** - Blocks shell metacharacters:
- Command chaining: `;`, `&&`, `||`
- Command substitution: `` ` ``, `$()`
- Dangerous redirects: `> /dev/`, `> /proc/`, `> /sys/`
- Piping to interpreters: `| bash`, `| python`, `| sh`
- Path bypasses detected via basename extraction

**Workarounds:**
- Use specialized tools: read_file instead of cat, search_files instead of grep
- For blacklisted commands needed for legitimate purposes, use Bash tool directly (if available)
- Simple pipes like `ps aux | grep python` are allowed
- Review blacklist in `local_agent.py` line 210-321 and remove commands you trust
- Review injection patterns in `local_agent.py` line 340-351 to adjust allowed patterns
- Most common commands (ls, pwd, echo, env, ps, netstat, ss, du, df, etc.) are allowed

### File not found when using read_file

**Symptoms:**
- Error: "File not found" or "No such file or directory"
- Agent can't locate specified file

**Solutions:**

1. **Use absolute paths:**
   ```
   Read /home/user/project/config.txt
   # Instead of: Read config.txt
   ```

2. **Find the file first:**
   ```
   Find files named config.txt
   # Then use the returned path with read_file
   ```

3. **Check current directory:**
   ```
   What's my current directory?
   # Verify you're in the expected location
   ```

### Search returns truncated results

**Symptoms:**
- Tool output ends with "... (output truncated)"
- Not all results shown

**Solutions:**

1. **Use more specific queries:**
   ```
   # Instead of: Search for "error"
   # Use: Search for "DatabaseError" in utils.py
   ```

2. **Use filters:**
   ```
   Search for "TODO" in Python files in the src directory
   ```

3. **Request specific files:**
   ```
   Read the specific file that contains what I'm looking for
   ```

## Performance Issues

### Agent is slow or unresponsive

**Possible causes and solutions:**

1. **Large model on limited hardware:**
   ```bash
   # Switch to smaller model
   ollama pull llama3.1:8b
   # Remove larger models to free RAM
   ollama rm llama3.1:70b
   ```

2. **Multiple models loaded:**
   ```bash
   # Limit concurrent models
   export OLLAMA_MAX_LOADED_MODELS=1
   ollama serve
   ```

3. **Long conversation history:**
   - Use `clear` command to reset history
   - Start new session for unrelated tasks

4. **Large tool outputs:**
   - Use more specific queries
   - Filter data before analysis
   - Leverage truncation and aggregation

### High memory usage

**Solutions:**

1. **Use smaller model:**
   ```bash
   ollama pull llama3.1:8b  # ~4.7GB
   # Instead of llama3.1:70b (~40GB)
   ```

2. **Monitor Ollama memory:**
   ```bash
   ps aux | grep ollama
   top -p $(pgrep ollama)
   ```

3. **Restart Ollama periodically:**
   ```bash
   pkill ollama
   ollama serve
   ```

## Debugging Tips

### Enable verbose logging

Add print statements in the agent loop to debug:

```python
# In local_agent.py or log_analyzer.py
print(f"Message history length: {len(messages)}")
print(f"Tool calls: {response.tool_calls}")
print(f"Iteration: {iteration}")
```

### Test tools independently

```python
# Test a tool outside the agent loop
from src.local_agent import web_search
result = web_search.invoke({"query": "test"})
print(result)
```

### Check Ollama logs

```bash
# If running Ollama as service
journalctl -u ollama -f

# If running manually
# Check terminal where ollama serve is running
```

### Verify tool binding

```python
# Check which tools are bound
print(llm_with_tools.kwargs['tools'])
```

## Getting Help

If issues persist:

1. Check the main documentation: `@CLAUDE.md`
2. Review setup instructions: `@SETUP.md`
3. Check usage examples: `@USAGE.md`
4. Review LangChain documentation: https://python.langchain.com/
5. Check Ollama documentation: https://ollama.ai/docs
6. Search for similar issues in project commit history
7. Test with minimal example to isolate the problem

## Common Error Messages Reference

| Error Message | Likely Cause | Solution |
|---------------|--------------|----------|
| "Could not connect to Ollama" | Ollama not running | `ollama serve` |
| "Model not found" | Model not installed | `ollama pull llama3.1:8b` |
| "No module named 'langchain'" | Dependencies not installed | `pip install langchain` |
| "SSH connection timed out" | SSH not configured | Configure SSH keys |
| "Permission denied" (journalctl) | User lacks journal access | Add to systemd-journal group |
| "Command not in whitelist" | Restricted command used | Use allowed alternatives |
| "File not found" | Wrong path or file | Use absolute paths |
| "Output truncated" | Result too large | Use more specific query |
