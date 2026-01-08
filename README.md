```markdown
# Mini STELLA CLI

A compact, local version of the STELLA Linux agent. This lightweight script (`stella-cli.py`) is intended for running smaller models locally (or via a local Ollama instance) to perform system administration tasks and execute controlled shell commands.

This repository is a smaller sibling of the larger [Stella-cli-docker](https://github.com/petyussz/Stella-cli-docker) project, which targets bigger models running in isolated Docker environments and adds features for remote host management. The Mini STELLA CLI focuses on a minimal, easy-to-run experience for development and experimentation.

**Features**

- Local LLM integration via Ollama (`langchain_ollama`).
- Safe command execution with sanitization and heuristic risk checks.
- Three operation modes: interactive REPL, single-shot CLI arguments, and piped input analysis.
- Rich terminal UI with Markdown rendering and themed output.
- Command history and navigation support via `prompt_toolkit`.

**Prompt Framework**

This project uses a concise prompt framework that encourages safe, auditable actions:

- The system prompt asks the model to "Plan" briefly (a short Chain-of-Thought style reasoning) before issuing any action.
- The model performs actions by invoking the `run_linux_command` tool; reasoning and execution are kept separate for safety and traceability.
- For each action the agent estimates `sudo` and `risk`; the tool enforces confirmations and additional sanitization where necessary.

**Requirements**

- Python 3.10+ (or compatible)
- Ollama running locally if using Ollama models (`ollama serve`).
- Python dependencies (see `requirements.txt`): `halo`, `langchain_ollama`, `langchain_core`, etc.

**Quick Start**

1. Install requirements:

   ```bash
   pip install -r requirements.txt
   ```

2. Ensure Ollama is running if using Ollama models:

   ```bash
   ollama serve
   ```

3. Run the agent:

   ```bash
   python stella-cli.py --model ministral-3:8b
   ```

**Operating Modes**

- **Interactive**: Start without arguments for a conversational REPL with history.
- **Single-shot**: Provide a prompt as arguments: `python stella-cli.py "what's my disk usage?"`
- **Piped Input**: Analyze output from other commands: `systemctl status | python stella-cli.py "troubleshoot this"`

**Flags**

- `--model`: Ollama model to use (default: `ministral-3:8b`).
- `--debug`: Show model reasoning and raw subprocess output.

**Usage Notes & Security**

- The script includes sanitization rules (timeouts for `ssh`, `curl`, `wget`, and `journalctl`/`systemctl` tweaks) and heuristic checks for high-risk patterns (e.g., recursive `rm`, `mkfs`, `dd`, writes to `/etc`).
- Elevated actions (`sudo`) and medium/high/critical-risk commands require explicit user confirmation.
- Interactive terminal programs (e.g., `vim`, `htop`) are blocked to avoid hanging the REPL.

**Recent Changes (High Level)**

- Added `sanitize_command` to automatically apply safe flags/timeouts for potentially hanging network or pager commands.
- Implemented heuristic safety overrides that flag critical patterns (recursive removal, filesystem formatting, low-level `dd`, writes to system directories) and escalate risk to require explicit confirmation.
- Switched the REPL to `prompt_toolkit` with `PromptSession` to provide command history and improved prompts.
- Improved conversation memory trimming to avoid orphaned tool outputs when pruning long histories.
- Added a `--debug` mode to expose model reasoning and raw subprocess stdout/stderr for troubleshooting.
- Startup now waits for the model to load (spinner) to ensure the LLM context is allocated before use.

**Security & Usage Notes**

- The CLI is conservative: it prevents launching interactive TUI programs and prompts the user before any risky or elevated operations.
- This script executes commands on the host — run it in a controlled environment and review commands before confirming execution.

**Development / Next Steps**

- Consider pinning versions in `requirements.txt` and adding unit tests for `sanitize_command` and safety heuristics.
- Optionally containerize for parity with the larger `Stella-cli-docker` project.

```
