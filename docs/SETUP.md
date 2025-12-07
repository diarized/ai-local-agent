# Setup Guide

Complete installation and environment setup for the AI agent project.

## Prerequisites

- Python 3.11 or higher
- Ollama installed and running
- SSH access to remote servers (for log analyzer only)

## Virtual Environment Setup

```bash
# Navigate to project directory
cd /path/to/ai-agent/src

# Activate the virtual environment
source venv/bin/activate

# Install/update dependencies
pip install langchain langchain-ollama langchain-core ddgs ollama
```

## Required Dependencies

Install all dependencies:

```bash
pip install -r requirements.txt
```

Or install individually:

- `langchain>=1.1.2` - Core LangChain framework
- `langchain-ollama>=1.0.0` - Ollama integration
- `langchain-core>=1.1.1` - Core abstractions
- `ddgs>=9.9.3` - DuckDuckGo search (for web_search tool)
- `ollama>=0.6.1` - Ollama Python client

## Ollama Setup

### Install Ollama

Follow instructions at: https://ollama.ai/

### Start Ollama Server

```bash
ollama serve
```

Verify Ollama is running:
```bash
curl http://localhost:11434/api/tags
```

### Pull Recommended Models

The agents will auto-select the first available model from the priority list. Install at least one:

```bash
# Recommended for general use (smaller, faster)
ollama pull llama3.1:8b

# Better reasoning capabilities (larger, slower)
ollama pull llama3.1:70b

# Alternative models
ollama pull qwen2.5:32b
ollama pull qwen3:14b
```

### Verify Model Installation

```bash
ollama list
```

You should see at least one model from the priority list.

## Model Selection Priority

Both agents try models in this order:
1. qwen3:14b
2. llama3.1:70b
3. llama3.1:8b
4. qwen2.5:32b

The first available model will be used.

## SSH Configuration (Log Analyzer Only)

For the log analyzer to fetch remote logs, configure SSH key authentication:

```bash
# Generate SSH key if you don't have one
ssh-keygen -t ed25519

# Copy public key to remote servers
ssh-copy-id user@zeus
ssh-copy-id user@hera
```

Verify SSH access:
```bash
ssh user@zeus journalctl -n 10
ssh user@hera journalctl -n 10
```

## Verification

Test that everything is working:

### Test General Agent
```bash
python src/local_agent.py
```

Type a simple query:
```
What's today's date?
```

If the agent responds with the current date, setup is complete.

### Test Log Analyzer
```bash
python src/log_analyzer.py
```

Type:
```
What tools do you have available?
```

The agent should list its tools including `fetch_remote_logs`.

## Directory Structure

Ensure the following structure exists:

```
ai-agent/
├── src/
│   ├── local_agent.py
│   └── log_analyzer.py
├── docs/
│   └── AI_VS_FAILBAN_COMPARISON.md
├── venv/
│   └── (virtual environment files)
└── requirements.txt
```

## Environment Variables

No environment variables are required. The agents use:
- Default Ollama endpoint: `http://localhost:11434`
- SSH: Uses system SSH configuration (~/.ssh/config)

## Performance Considerations

### Model Size vs Performance

- **llama3.1:8b**: ~4.7GB, fast responses, suitable for most tasks
- **llama3.1:70b**: ~40GB, better reasoning, requires significant RAM
- **qwen2.5:32b**: ~18GB, balanced performance

Choose based on your hardware:
- 8GB RAM: Use llama3.1:8b
- 16GB RAM: Use llama3.1:8b or qwen2.5:32b
- 32GB+ RAM: Any model, including llama3.1:70b

### Ollama Performance Tuning

```bash
# Increase context window (if needed)
ollama run llama3.1:8b --context 32768

# Limit concurrent requests
export OLLAMA_MAX_LOADED_MODELS=1
```

## Next Steps

Once setup is complete, see `@USAGE.md` for detailed usage examples and tool documentation.
