# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI agent experimentation environment using LangChain 1.0+ with Ollama for local LLM inference. Two specialized agents: general-purpose interactive assistant and security-focused log analyzer.

**Stack:** Python 3.11+, LangChain 1.1+, Ollama, DuckDuckGo Search
**Status:** Active development

## Project Type and Domain

**Category:** Software Development / AI Research
**Domain:** LLM agent orchestration, security analysis
**Methodology:** Manual agent loop pattern (non-LangGraph)
**Stack:** Python, LangChain, Ollama (local inference)

## Project Structure

```
.
├── src/
│   ├── local_agent.py      # General-purpose agent with web search, file ops, shell commands
│   └── log_analyzer.py     # Security log analysis agent with remote log fetching
├── docs/
│   └── AI_VS_FAILBAN_COMPARISON.md  # Technical comparison document
├── venv/                   # Python virtual environment
├── @SETUP.md               # Installation and environment setup
├── @USAGE.md               # Detailed usage examples and tool documentation
└── @TROUBLESHOOTING.md     # Common issues and solutions
```

## Key Concepts and Terminology

**Agent Loop:** Manual tool-calling loop (user input → LLM → tool calls → results → loop back)
**Tool Binding:** LangChain pattern using `llm.bind_tools(tools)` to enable function calling
**Context Window Management:** Token estimation and truncation strategies for 32k context limit
**Log Aggregation:** Intelligent sampling methods (errors_only, sample, unique_ips, time_windows)

## Architecture

### Agent Loop Pattern
Both agents implement manual agent loops (not LangGraph):

1. User input → `HumanMessage` added to history
2. LLM invoked with message history
3. If tool calls returned:
   - Execute via `execute_tool_call()`
   - Add `ToolMessage` to history
   - Loop back (max 10-15 iterations)
4. Return final response when no tool calls

### Tool Definition Pattern
```python
@tool
def tool_name(param: str) -> str:
    """Tool description for LLM.

    Args:
        param: Parameter description
    """
    return result
```

### Model Selection
Auto-select first available model from priority list:
- qwen3:14b → llama3.1:70b → llama3.1:8b → qwen2.5:32b

### Context Window Management

**General Agent (`local_agent.py`):**
- Token estimation: 1 token ≈ 4 chars
- Automatic truncation: 6000 token limit per tool output
- Truncation warnings with suggestions for specific queries

**Log Analyzer (`log_analyzer.py`):**
- Statistical summaries via `create_log_summary` (no raw logs)
- Intelligent aggregation via `aggregate_logs`:
  - `errors_only`: Filter to security-relevant entries (401/403/404/500)
  - `sample`: First 100 + random middle 100 + last 100 lines
  - `unique_ips`: One line per unique IP
  - `time_windows`: Distribute samples across time periods

### Log Analysis Capabilities

Beyond regex-based tools (fail2ban), detects:
- **Slow scanning** - Attacks spread over hours
- **Distributed attacks** - Coordinated IPs from same subnet
- **Statistical anomalies** - Z-score deviation from baseline
- **Behavioral patterns** - SQL injection, credential stuffing
- **Context awareness** - Attack intent vs pattern matching

See `docs/AI_VS_FAILBAN_COMPARISON.md` for detailed comparison.

## Key Implementation Details

### General Agent Tools (`local_agent.py`)
- `web_search` - DuckDuckGo search
- `run_shell_command` - Shell commands (blacklist-restricted: blocks rm, sudo, shutdown, apt, python, wget, etc.)
- `search_files` - Grep for file contents (.txt, .py, .md only)
- `find_files` - Find files by pattern (max 50 results)
- `read_file` - Read text files (max 1MB)
- `get_system_info` - OS, CPU, memory, disk info
- `get_more_data` - Retrieve additional pages from paginated output

### Log Analyzer Tools (`log_analyzer.py`)
- `fetch_remote_logs` - SSH to servers (zeus, hera) via journalctl
- `create_log_summary` - Statistical overview without raw logs
- `aggregate_logs` - Reduce logs for context window
- `analyze_log_patterns` - Parse Apache/Nginx/Postfix/Dovecot logs
- `detect_anomalies` - Z-score based anomaly detection
- `check_ip_reputation` - Basic IP reputation checks
- `generate_fail2ban_rule` - Generate filter rules from patterns
- `save_analysis_report` - Save results to file

### Security Constraints
- `run_shell_command` blacklist: Blocks destructive ops (rm, dd), system modification (shutdown, sudo, chmod), network changes (iptables, ip), package management (apt, pip, npm), code execution (python, bash, gcc), file downloads (wget, curl, git), database clients, text editors, and other risky operations
- `run_shell_command` injection protection: Detects and blocks shell metacharacters (;, &&, ||, `, $(), pipes to interpreters) and path-based bypasses (/bin/rm)
- Shell command timeout: 30 seconds
- `search_files` restricted to .txt, .py, .md files
- `find_files` limited to first 50 results
- `read_file` max size: 1MB, text files only

## Development Guidelines

### Adding New Tools
1. Define with `@tool` decorator from `langchain_core.tools`
2. Add comprehensive docstring (LLM uses this for selection)
3. Add to tools list before `llm.bind_tools()`
4. Add to `execute_tool_call()` tool_map

### Modifying Agent Behavior
- **System message:** Edit to change agent personality/focus
- **Temperature:** Currently 0 (deterministic), increase for creativity
- **Max iterations:** 10 (general agent), 15 (log analyzer)

### Tool Binding
```python
tools = [tool1, tool2, tool3]
llm_with_tools = llm.bind_tools(tools)
```

### Tool Execution
```python
tool_func = tool_map[tool_name]
result = tool_func.invoke(args)  # LangChain's .invoke() method
```

### Testing Tools Independently
```python
from src.local_agent import web_search
result = web_search.invoke({"query": "test query"})
```

## Conventions and Standards

### File Naming
- Agent files: `{purpose}_agent.py` (e.g., `local_agent.py`, `log_analyzer.py`)
- Documentation: Markdown format (per user's global CLAUDE.md)

### Code Style
- Temperature: 0 for deterministic responses
- Tool docstrings: Complete with Args section
- Error handling: All tool functions return error strings on failure
- Message history: Use LangChain message types (`HumanMessage`, `AIMessage`, `ToolMessage`)

### Agent Loop
- Max iterations explicitly defined in loop
- Clear iteration tracking in output
- Tool execution errors returned as strings to LLM

## Common Tasks

### Running Agents
See `@USAGE.md` for detailed examples.

**General agent:**
```bash
python src/local_agent.py
```

**Log analyzer:**
```bash
python src/log_analyzer.py
```

### Testing New Tools
1. Define tool with `@tool` decorator
2. Test standalone: `tool.invoke({"param": "value"})`
3. Add to agent's tools list
4. Add to `execute_tool_call()` mapping
5. Test in agent loop

### Debugging Agent Loops
- Check message history length
- Verify tool_map contains all bound tools
- Review tool docstrings for clarity
- Monitor iteration count

## Setup and Dependencies

See `@SETUP.md` for:
- Virtual environment setup
- Required dependencies
- Ollama installation and model setup

## Troubleshooting

See `@TROUBLESHOOTING.md` for common issues and solutions.

## Version Information

**Last Updated:** 2025-12-07
**Project Phase:** Active Development
**Python Version:** 3.11+
**LangChain Version:** 1.1.2+
