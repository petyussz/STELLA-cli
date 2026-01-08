# Mini STELLA CLI

A compact, local version of the STELLA Linux agent. This lightweight script (`stella-cli.py`) is designed to run smaller models locally (or via a local Ollama instance) to perform system administration tasks and execute controlled shell commands.

This repository is a smaller sibling of the larger [Stella-cli-docker](https://github.com/petyussz/Stella-cli-docker) project. While the Docker version targets bigger models in isolated environments with remote host management, **Mini STELLA CLI** focuses on a minimal, easy-to-run experience for development and experimentation.

---

## Key Features

* **Local LLM Integration:** Powered by Ollama (`langchain_ollama`) for privacy and speed.
* **Safe Command Execution:** Includes sanitization, heuristic risk checks, and blocked interactive programs.
* **Three Operation Modes:** Interactive REPL, Single-shot CLI, and Piped Input analysis.
* **Rich Terminal UI:** Features Markdown rendering, themed output, and spinners.
* **History & Navigation:** Robust command history support via `prompt_toolkit`.

---

## Installation

### Requirements
* **Python:** 3.10+ (or compatible)
* **Ollama:** Must be installed and running locally (`ollama serve`).
* **Dependencies:** `halo`, `langchain_ollama`, `langchain_core` (see `requirements.txt`).

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
* `--debug`: Enable debug mode to view model reasoning, raw subprocess output, and internal logs.

---

## Safety & Security Architecture

The CLI is designed to be conservative. It executes commands directly on the host, so strictly controlled environments and user review are essential.

### Safety Mechanisms
* **Heuristic Risk Checks:** The system flags critical patterns (e.g., recursive `rm`, `mkfs`, `dd`, writes to `/etc`) and escalates them to require explicit confirmation.
* **Command Sanitization:** Automatically applies timeouts and safe flags to potentially hanging network commands (e.g., `curl`, `wget`) or paging tools (`journalctl`).
* **Blocked Programs:** Interactive TUI programs (e.g., `vim`, `htop`, `nano`) are blocked to prevent the REPL from hanging.
* **Elevation Control:** Any action requiring `sudo` or deemed Medium/High/Critical risk triggers a user confirmation prompt.

### Prompt Framework
This project uses a concise framework to ensure auditable actions:
1.  **Plan:** The system prompt requires the model to provide a short "Chain-of-Thought" plan.
2.  **Tool Use:** Actions are performed strictly by invoking the `run_linux_command` tool.
3.  **Separation:** Reasoning and execution are kept separate for safety and traceability.

---

## Development Status

### Recent Updates
* **Enhanced Safety:** Implemented heuristic overrides for high-risk filesystem operations.
* **REPL Upgrade:** Switched to `prompt_toolkit` with `PromptSession` for better history navigation.
* **Debug Mode:** Added `--debug` to expose model reasoning and subprocess stdout/stderr.
* **Startup:** Added initialization spinners to ensure LLM context is ready before user input.
* **Memory Management:** Improved conversation trimming to handle long histories without orphaning tool outputs.

### Next Steps
* Pin versions in `requirements.txt`.
* Add unit tests for `sanitize_command` and safety heuristics.
* Optionally containerize for parity with the larger `Stella-cli-docker` project.