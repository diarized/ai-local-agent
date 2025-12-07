# AI Local Agent

**Local LLM-powered AI agents with Ollama on workstation hardware**

Dual-agent system for general-purpose assistance and security log analysis using LangChain 1.0+ with Ollama for local LLM inference. Optimized for workstations with Xeon processors and dual NVIDIA GPUs.

## Hardware Requirements

### Recommended Configuration
- **CPU:** Intel Xeon E5 or equivalent (multi-core server processors)
- **GPU:** 2x NVIDIA 4060Ti 24GB VRAM (48GB total)
- **RAM:** 32GB+ system memory
- **Storage:** 200GB+ free space for models
- **OS:** Linux (Ubuntu 22.04+, tested on Linux 6.8.0-88-generic)

### Minimum Configuration
- **CPU:** 4+ cores
- **GPU:** Single NVIDIA GPU with 24GB+ VRAM
- **RAM:** 16GB system memory
- **Storage:** 50GB+ free space

This project is specifically designed for workstation deployments where local inference are priorities.

## Features

### General-Purpose Agent (`local_agent.py`)
Interactive assistant with system integration capabilities:

- **Web Search:** DuckDuckGo integration for current information
- **File Operations:** Search, find, and read files (supports .txt, .py, .md)
- **Shell Commands:** Secure command execution with blacklist-based protection
- **System Information:** CPU, memory, disk usage monitoring
- **Pagination:** Intelligent handling of large outputs with context window management

**Security:** Comprehensive command blacklisting blocks destructive operations (rm, dd), system modification (sudo, chmod), package management (apt, pip), code execution (python, bash), and injection attempts (shell metacharacters, path bypasses).

### Security Log Analyzer (`log_analyzer.py`)
Specialized agent for security log analysis with advanced detection capabilities:

- **Remote Log Fetching:** SSH-based log retrieval via journalctl (Apache, Nginx, Postfix, Dovecot)
- **Intelligent Aggregation:** Multiple strategies for context window management:
  - `errors_only`: Filter to security-relevant entries (401/403/404/500)
  - `sample`: Distributed sampling (first 100 + random 100 + last 100)
  - `unique_ips`: One example per unique IP address
  - `time_windows`: Temporal distribution for trend analysis
- **Pattern Analysis:** Parse and analyze Apache/Nginx/Postfix/Dovecot logs
- **Anomaly Detection:** Z-score based statistical anomaly detection
- **IP Reputation:** Basic IP reputation checking
- **Fail2ban Integration:** Generate filter rules from detected patterns
- **Report Export:** Save analysis results to files

**Advantages over traditional tools (fail2ban, regex):**
- Detects slow scanning attacks (distributed over hours)
- Identifies coordinated attacks from multiple IPs in same subnet
- Statistical anomaly detection beyond simple pattern matching
- Behavioral pattern recognition (SQL injection, credential stuffing)
- Context-aware analysis of attack intent

See `docs/AI_VS_FAILBAN_COMPARISON.md` for detailed comparison.

## Quick Start

### 1. Install Ollama

```bash
# Download and install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama server
ollama serve
```

### 2. Configure Dual GPU Setup

Ollama automatically detects and uses all available GPUs. For dual 4060Ti 24GB setup:

```bash
# Verify GPU detection
nvidia-smi

# Check Ollama sees both GPUs
curl http://localhost:11434/api/tags

# Optional: Set specific GPU allocation
export CUDA_VISIBLE_DEVICES=0,1
```

### 3. Pull Models (Recommended for 48GB VRAM)

```bash
# Best for reasoning tasks - uses both GPUs efficiently
ollama pull llama3.1:70b        # ~40GB VRAM, excellent reasoning

# Fast and efficient - single GPU
ollama pull llama3.1:8b         # ~4.7GB VRAM, quick responses

# Balanced option
ollama pull qwen2.5:32b         # ~18GB VRAM, good performance

# Alternative high-quality model
ollama pull qwen3:14b           # ~8GB VRAM, fast and capable
```

**Recommendation for Xeon E5 + 2x 4060Ti (48GB VRAM):**
- **Primary:** `llama3.1:70b` (uses both GPUs, best reasoning)
- **Secondary:** `qwen2.5:32b` (single GPU, faster responses)
- **Testing:** `llama3.1:8b` (minimal resources, quick iteration)

### 4. Setup Python Environment

```bash
# Navigate to project directory
cd /path/to/ai-local-agent

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install langchain>=1.1.2 langchain-ollama>=1.0.0 langchain-core>=1.1.1 ddgs>=9.9.3 ollama>=0.6.1
```

### 5. Run Agents

**General-purpose agent:**
```bash
python src/local_agent.py
```

**Security log analyzer:**
```bash
python src/log_analyzer.py
```

## Model Selection

Both agents auto-select the first available model from this priority list:
1. `qwen3:14b`
2. `llama3.1:8b`
3. `qwen2.5:32b`

### Model Performance on Xeon E5 + 2x 4060Ti (48GB VRAM)

| Model | VRAM | GPUs | Speed | Quality | Use Case |
|-------|------|------|-------|---------|----------|
| qwen2.5:32b | ~18GB | 1 | Medium | Very Good | Balanced workloads |
| qwen3:14b | ~8GB | 1 | Fast | Good | General tasks |
| llama3.1:8b | ~4.7GB | 1 | Very Fast | Good | Quick queries, testing |

## Architecture

### Agent Loop Pattern
Manual tool-calling loop (not LangGraph-based):

```
User Input → HumanMessage
    ↓
LLM Inference (with bound tools)
    ↓
Tool Calls? → Yes → Execute Tools → Add ToolMessage → Loop (max 10-15 iterations)
    ↓ No
Final Response
```

### Context Window Management

**General Agent:**
- Token estimation: 1 token ≈ 4 chars
- Automatic truncation: 6000 token limit per tool output
- Truncation warnings with specific query suggestions

**Log Analyzer:**
- Statistical summaries for large datasets
- Intelligent aggregation methods (errors_only, sample, unique_ips, time_windows)
- No raw log dumps to conserve context window

### Tool Execution

Tools defined using LangChain's `@tool` decorator:
```python
@tool
def tool_name(param: str) -> str:
    """Tool description for LLM.

    Args:
        param: Parameter description
    """
    return result
```

## Usage Examples

### General Agent

```bash
$ python src/local_agent.py

You: What files are in the current directory?
Agent: [Uses run_shell_command: ls -la]
Agent: Shows directory listing...

You: Search for Python files containing 'agent'
Agent: [Uses search_files with grep]
Agent: Found 2 files: local_agent.py, log_analyzer.py

You: What are the latest LangChain best practices?
Agent: [Uses web_search]
Agent: Returns search results from DuckDuckGo
```

### Log Analyzer

```bash
$ python src/log_analyzer.py

You: Analyze Apache logs from zeus for suspicious activity
Agent: [Fetches logs via fetch_remote_logs]
Agent: [Creates summary - 15,432 entries found]
Agent: [Aggregates using errors_only - reduced to 847 entries]
Agent: [Analyzes patterns]
Agent: Detected 3 suspicious IPs with repeated 404 scanning...

You: Generate a fail2ban rule for these attacks
Agent: [Uses generate_fail2ban_rule]
Agent: Generated filter rule for /admin/* path scanning

You: Save the analysis
Agent: [Uses save_analysis_report]
Agent: Saved to analysis_report_20251207.txt
```

## Ollama Performance Tuning

### GPU Memory Management

```bash
# Monitor GPU usage during inference
watch -n 1 nvidia-smi

# Set specific GPU allocation (if needed)
export CUDA_VISIBLE_DEVICES=0,1  # Use both GPUs
export CUDA_VISIBLE_DEVICES=0    # Use only first GPU
```

### Ollama Configuration

```bash
# Increase context window for large log analysis
ollama run qwen3:14b --context 32768

# Limit concurrent model loading (recommended for multi-GPU)
export OLLAMA_MAX_LOADED_MODELS=1

# Set number of GPU layers (auto-detected by default)
ollama run llama3.1:70b --gpu-layers 80
```

### Performance Tips for Xeon E5 Workstations

- **CPU Affinity:** Pin Ollama to specific cores if running other workloads
- **Cooling:** Monitor GPU temps during long inference sessions (70b models)
- **Power:** Ensure adequate PSU for dual 4060Ti (320W+ recommended)
- **VRAM Monitoring:** Use `nvidia-smi` to track utilization
- **Model Switching:** Keep multiple models pulled; switch based on task complexity

## Directory Structure

```
ai-local-agent/
├── src/
│   ├── local_agent.py           # General-purpose interactive agent
│   └── log_analyzer.py          # Security log analysis agent
├── docs/
│   ├── SETUP.md                 # Detailed setup instructions
│   ├── USAGE.md                 # Comprehensive usage guide
│   ├── TROUBLESHOOTING.md       # Common issues and solutions
│   ├── AI_VS_FAILBAN_COMPARISON.md  # AI vs regex comparison
│   ├── SECURITY_FIXES.md        # Security vulnerability documentation
│   └── SHELL_BLACKLISTING.md    # Command blacklist details
├── venv/                        # Python virtual environment
├── requirements.txt             # Python dependencies
├── CLAUDE.md                    # Project documentation for Claude Code
└── README.md                    # This file
```

## Documentation

- **[SETUP.md](docs/SETUP.md)** - Complete installation guide
- **[USAGE.md](docs/USAGE.md)** - Detailed usage examples and tool documentation
- **[TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[AI_VS_FAILBAN_COMPARISON.md](docs/AI_VS_FAILBAN_COMPARISON.md)** - Technical comparison with traditional tools
- **[SECURITY_FIXES.md](docs/SECURITY_FIXES.md)** - Security vulnerability fixes
- **[SHELL_BLACKLISTING.md](docs/SHELL_BLACKLISTING.md)** - Command blacklist implementation

## Security Considerations

### General Agent
- Blacklist-based command filtering (destructive, system modification, package management)
- Shell injection protection (metacharacters, command substitution, path bypasses)
- File operation restrictions (.txt, .py, .md only for search)
- 30-second command timeout
- 1MB file size limit for reads

### Log Analyzer
- SSH key authentication required (no password auth)
- Read-only log access via journalctl
- No direct shell access to remote servers
- Reports saved to local filesystem only

## Development

### Adding New Tools

1. Define tool with `@tool` decorator
2. Add comprehensive docstring (LLM uses this)
3. Add to tools list before `llm.bind_tools()`
4. Add to `execute_tool_call()` tool_map

Example:
```python
@tool
def my_tool(param: str) -> str:
    """Tool description for LLM.

    Args:
        param: Parameter description
    """
    return f"Result: {param}"
```

### Testing

```python
# Test tool independently
from src.local_agent import web_search
result = web_search.invoke({"query": "test"})

# Test agent loop
python src/local_agent.py
```

## Technical Stack

- **Python:** 3.11+
- **LangChain:** 1.1.2+ (core framework)
- **Ollama:** 0.6.1+ (local LLM inference)
- **DuckDuckGo:** 9.9.3+ (web search)
- **CUDA:** 12.x (for NVIDIA GPU support)

## Project Status

**Status:** Active Development
**Last Updated:** 2025-12-07
**Tested On:** Linux 6.8.0-88-generic, Xeon E5, 2x NVIDIA 4060Ti 24GB

## License

This project is experimental software for research and educational purposes.

## Contributing

This is a personal experimentation project. For issues or suggestions, please create an issue in the repository.

## Credits

Built with:
- [LangChain](https://github.com/langchain-ai/langchain) - LLM orchestration framework
- [Ollama](https://ollama.ai/) - Local LLM inference engine
- [DuckDuckGo Search](https://github.com/deedy5/duckduckgo_search) - Privacy-focused search
