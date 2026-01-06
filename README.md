# Mini STELLA CLI

A compact, local version of the STELLA Linux agent. This lightweight script (`stella-cli.py`) is intended for running smaller models locally (or via a local Ollama instance) to perform system administration tasks and execute controlled shell commands.

This repository is a smaller sibling of the larger [Stella-cli-docker](https://github.com/petyussz/Stella-cli-docker) project, which targets bigger models running in isolated Docker environments and adds features for remote host management. The Mini STELLA CLI focuses on a minimal, easy-to-run experience for development and experimentation.

**Features**

- Local LLM integration via Ollama (`langchain_ollama`).
- Safe command execution with sanitization and heuristic risk checks.
- Simple interactive REPL with history and optional debug output.

**Requirements**

- Python 3.10+ (or compatible)
- Ollama running locally if using Ollama models (`ollama serve`).
- Python dependencies (see `requirements.txt`): `halo`, `langchain_ollama`, `langchain_core`, etc.

**Quick Start**

1. Install requirements:

   pip install -r requirements.txt

2. Ensure Ollama is running if using Ollama models:

   ollama serve

3. Run the agent:

   python stella-cli.py --model ministral-3:8b

Flags:

- `--model`: Ollama model to use (default: `ministral-3:8b`).
- `--debug`: Show model reasoning and raw subprocess output.

**Usage Notes & Security**

- The script includes sanitization rules (timeouts for `ssh`, `curl`, `wget`, and `journalctl`/`systemctl` tweaks) and a set of heuristic checks for high-risk patterns (e.g., recursive `rm`, `mkfs`, `dd`, writes to `/etc`).
- Elevated actions (`sudo`) and medium/high/critical-risk commands require explicit user confirmation.
- Interactive terminal programs (e.g., `vim`, `htop`) are blocked to avoid hanging the REPL.

**Differences vs Stella-cli-docker**

- Mini version runs directly on the host (no Docker orchestration).
- Designed for smaller, local model usage rather than large models in isolated containers.
- Fewer components and simpler deployment for quick experimentation.

**Development / Next steps**

- Consider updating `requirements.txt` to pin tested versions.
- Add unit tests for `sanitize_command` and the safety heuristics.
- Optionally, containerize this script for deployment parity with the larger project.

**License**
Repo inherits the author's preferred license. Check the original project for licensing details.

---
File: `stella-cli.py` is the main entry point for the agent.
