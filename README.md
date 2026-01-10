# STELLA (Simple Terminal LLM Agent)

A lightweight, standalone STELLA Linux agent. This script (`stella-cli.py`) is designed to run smaller models locally (or via a local Ollama instance) to perform system administration tasks and execute controlled shell commands with safety and transparency.

---

## Key Features

* **Local LLM Integration:** Powered by Ollama (`langchain_ollama`) for privacy and speed.
* **Three Tools:** `run_linux_command`, `run_remote_command`, and `write_file` for flexible task execution.
* **Three Operation Modes:** Interactive REPL, Single-shot CLI, and Piped Input analysis.
* **Smart Safety:** Heuristic risk checks, command sanitization, confirmation prompts, and blocked interactive programs.
* **Rich Terminal UI:** Markdown rendering, themed output, spinners, and history navigation via `prompt_toolkit`.

---

## Installation

### Requirements
* **Python:** 3.10+ (or compatible)
* **Ollama:** Must be installed and running locally (`ollama serve`).
* **Dependencies:** see `requirements.txt`.

### Quick Start

1.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Ensure Ollama is running:**
    ```bash
    ollama serve
    ```

3.  **Run the agent:**
    ```bash
    python stella-cli.py --model ministral-3:8b
    ```

---

## Usage Guide

### Operating Modes

| Mode | Description | Example |
| :--- | :--- | :--- |
| **Interactive** | Start a conversational REPL with history. | `python stella-cli.py` |
| **Single-shot** | Provide a prompt as a command-line argument. | `python stella-cli.py "what's my disk usage?"` |
| **Piped Input** | Analyze output from other commands. | `systemctl status \| python stella-cli.py "troubleshoot this"` |

### Command Line Flags

* `--model`: Specify the Ollama model to use (default: `ministral-3:8b`).
* `--ctx`: Set context window size in tokens (default: `4096`).
* `--debug`: View model reasoning, subprocess output, and internal logs.

### Remote Execution

STELLA can execute commands on remote servers via SSH. The model can transparently choose between local and remote execution based on your instructions:

```bash
python stella-cli.py "check disk usage on prod-server-01"
```

The agent will use the `run_remote_command` tool with:
* **Host & User:** Specify in your prompt (e.g., "on admin@prod-server-01"), or reference hosts from a JSON inventory file at `~/managed_hosts.json`
* **Sudo:** Automatically escalated if needed (requires SSH key-based auth or cached credentials)
* **Timeouts:** SSH connections timeout after 10 seconds to prevent hanging

**Requirements:** SSH keys configured for passwordless access to target hosts.

---

## Safety & Security Architecture

The CLI is designed to be conservative. It executes commands directly on the host, so strictly controlled environments and user review are essential.

### Safety Mechanisms
* **Risk Escalation:** Critical patterns (`rm -r`, `mkfs`, `dd`, writes to `/etc`, etc.) require explicit user confirmation.
* **Environment Variable Hardening:** All commands execute with safe Linux environment variables:
  - `PAGER=cat` and `SYSTEMD_PAGER=cat`: Prevents pagers from hanging waiting for input
  - `TERM=dumb`: Forces non-interactive output mode
  - `PYTHONUNBUFFERED=1`: Ensures unbuffered output for real-time feedback
* **Command Sanitization:** Auto-applies protective flags:
  - `curl` / `wget`: 60-second timeout on network operations
  - `systemctl`: Adds `--full (-l)` to prevent line truncation
  - `sudo`: Automatically enforces `-E` flag to preserve safe environment variables through privilege escalation
* **Blocked Programs:** `vim`, `nano`, `htop`, `less`, `more`, `watch`, and other interactive TUIs blocked.
* **Sudo Handling:** Prompts for authentication when needed; caches credentials for session.
* **Path Safety:** `write_file` blocks writes to `/etc`, `/boot`, `/usr`, `/var/lib`.
* **Elevation Control:** Any `sudo` or High/Critical risk action requires confirmation (interactive mode only).

### Prompt Framework
The system uses a structured execution model:
1. **Planning:** Model produces a brief Chain-of-Thought plan.
2. **Tool Invocation:** Actions executed via tools (`run_linux_command`, `run_remote_command`, `write_file`).
3. **Transparency:** All tool calls and outcomes are logged for audit and review.

---

## Development Status

### Recent Updates
* **Linux Environment Hardening:** Subprocess execution now injects safe environment variables (`PAGER=cat`, `TERM=dumb`, etc.) at the OS level rather than relying solely on command-line sanitization. This is more robust and simpler to maintain.
* **Enhanced Command Sanitization:** Auto-applies `sudo -E`, `systemctl --full`, and network timeouts as auxiliary protections.
* **Four Tools:** `run_linux_command`, `run_remote_command`, `read_file`and `write_file` for flexible task execution.
* **Heuristic Risk Detection:** Analyzes commands for critical patterns and blocks potentially dangerous operations until user confirms.
* **Spinners & Status:** Real-time feedback during LLM thinking and command execution.
* **History & REPL:** `prompt_toolkit` integration for command history and improved navigation.