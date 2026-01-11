import subprocess
import os
import re
import sys
import argparse
import shlex
import json
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_core.callbacks import BaseCallbackHandler
from langchain.agents import create_agent

# --- RICH UI IMPORTS ---
from rich.console import Console
from rich.markdown import Markdown
from rich.theme import Theme
from rich.panel import Panel

# --- PROMPT TOOLKIT ---
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.formatted_text import HTML

# --- THEME CONFIGURATION ---
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "command": "bold yellow",
})
console = Console(theme=custom_theme)


# --- CUSTOM EXCEPTION ---
class UserAbort(Exception):
    pass


# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="STELLA Linux Agent")
parser.add_argument("--model", type=str, default="ministral-3:8b", help="Ollama model to use")
parser.add_argument("--debug", action="store_true", help="Show raw reasoning and subprocess output")
parser.add_argument("--ctx", type=str, default="4096", help="Context length for the model")
parser.add_argument("--keepalive", type=str, default="5m", help="Ollama keepalive (0 for permanent)")
parser.add_argument("prompt", nargs="*", help="Direct prompt for non-interactive mode")
# Use parse_known_args in case pytest injects weird args, though mocking argv usually handles this
args, _ = parser.parse_known_args()

# --- CONFIGURATION ---
MODEL = args.model
DEBUG = args.debug
MAX_HISTORY = 50
CTX_LENGTH = int(args.ctx)
SUBPROCESS_TIMEOUT = 30
SSH_CONN_TIMEOUT = 10
WGET_CURL_TIMEOUT = 60
OLLAMA_KEEPALIVE = args.keepalive


# --- SPINNER & DEBUG HANDLER ---
class SpinnerHandler(BaseCallbackHandler):
    """
    Handles UI feedback.
    Normal Mode: Shows a spinner when thinking.
    Debug Mode: Prints raw chain-of-thought and tool inputs/outputs.
    """

    def __init__(self, console):
        self.console = console
        self.status = None

    def on_llm_start(self, serialized, prompts, **kwargs):
        if DEBUG:
            self.console.print(f"[dim magenta][DEBUG] LLM Input (Truncated):[/dim magenta] {str(prompts[0])[:200]}...")
        else:
            self.status = self.console.status("[dim]Thinking...[/dim]", spinner="dots")
            self.status.start()

    def on_llm_end(self, response, **kwargs):
        if self.status:
            self.status.stop()

        if DEBUG:
            try:
                text = response.generations[0][0].text
                self.console.print(Panel(text, title="[magenta]Raw Reasoning[/magenta]", border_style="dim magenta"))
            except:
                pass

    def on_tool_start(self, serialized, input_str, **kwargs):
        if self.status:
            self.status.stop()

        if DEBUG:
            self.console.print(f"[bold magenta][DEBUG] Tool Call:[/bold magenta] {serialized.get('name')}")
            self.console.print(f"[dim magenta]Input: {input_str}[/dim magenta]")

    def on_tool_end(self, output, **kwargs):
        if DEBUG:
            self.console.print(f"[bold magenta][DEBUG] Tool Output (Truncated):[/bold magenta] {str(output)[:200]}...")

    def on_llm_error(self, error, **kwargs):
        if self.status:
            self.status.stop()
        if DEBUG:
            self.console.print(f"[bold red][DEBUG] LLM Error:[/bold red] {error}")


# --- HELPER FUNCTIONS ---

def truncate_output(text: str) -> str:
    """Smartly truncates output. In DEBUG mode, returns full text."""
    if DEBUG:
        console.print(f"[dim magenta][DEBUG] Output Length: {len(text)} chars (No Truncation)[/dim magenta]")
        return text

    MAX_CHARS = int(CTX_LENGTH * 3)
    if len(text) <= MAX_CHARS:
        return text

    half = MAX_CHARS // 2
    return f"{text[:half]}\n\n... [TRUNCATED {len(text) - MAX_CHARS} CHARS] ...\n\n{text[-half:]}"


def sanitize_command(cmd: str) -> str:
    """Sanitizes commands for safety (Sudo -E, Timeouts, Systemctl -l)."""
    cmd = cmd.strip()

    # Rule 1: Sudo -E
    if re.search(r"\bsudo\b", cmd) and "-E" not in cmd:
        cmd = re.sub(r"\bsudo\b", "sudo -E", cmd)

    # Rule 2: Systemctl
    if re.search(r"\bsystemctl\b", cmd) and not re.search(r" -l\b| --full\b", cmd):
        cmd = re.sub(r"\bsystemctl\b", "systemctl -l", cmd, count=1)

    # Rule 3: Curl Timeout
    if re.search(r"\bcurl\b", cmd) and not re.search(r"(--max-time|-m)\s+\d+", cmd):
        cmd = re.sub(r"\bcurl\b", f"curl --max-time {WGET_CURL_TIMEOUT}", cmd, count=1)

    # Rule 4: Wget Timeout
    if re.search(r"\bwget\b", cmd) and not re.search(r"(--timeout|-T)[=\s]+\d+", cmd):
        cmd = re.sub(r"\bwget\b", f"wget --timeout={WGET_CURL_TIMEOUT}", cmd, count=1)

    return cmd


def analyze_risk(cmd: str) -> str:
    """Analyzes command safety. Catches 'mkfs.ext4', 'rm -rf', etc."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return "critical"

    commands_to_check = []
    if tokens:
        commands_to_check.append(tokens[0])

    for i, token in enumerate(tokens):
        if token == "|" and i + 1 < len(tokens):
            commands_to_check.append(tokens[i + 1])
        if token in ["sudo", "sudo -E"] and i + 1 < len(tokens):
            commands_to_check.append(tokens[i + 1])

    CRITICAL_BINARIES = {
        "mkfs", "dd", "shutdown", "reboot", "init",
        "chmod", "chown", "wget", "curl", "mv", "cp"
    }

    for cmd_verb in commands_to_check:
        # Improved Logic: Check exact match OR startswith "cmd." (e.g., mkfs.ext4)
        if any(cmd_verb == crit or cmd_verb.startswith(crit + ".") for crit in CRITICAL_BINARIES):
            return "critical"

        if cmd_verb == "rm":
            if any(flag in tokens for flag in ["-r", "-R", "-rf", "-fr"]):
                return "critical"

    if ">" in tokens:
        idx = tokens.index(">")
        if idx + 1 < len(tokens):
            target = tokens[idx + 1]
            if target.startswith(("/etc", "/boot", "/usr", "/var")):
                return "critical"

    return "low"


def wait_for_model_load(llm_instance):
    with console.status(f"[dim]Loading {llm_instance.model}...[/dim]", spinner="dots"):
        try:
            llm_instance.invoke("Hi")
        except Exception as e:
            console.print(f"[bold red]Error loading model: {e}[/bold red]")
            sys.exit(1)


# --- TOOLS ---

@tool
def run_linux_command(cmd: str, sudo: bool = False) -> str:
    """Executes a LOCAL Linux shell command."""
    cmd = cmd.strip()

    if cmd.startswith("cd "):
        try:
            os.chdir(os.path.expanduser(cmd[3:].strip()))
            return f"Success: Changed directory to {os.getcwd()}"
        except Exception as e:
            return f"Error changing directory: {e}"

    cmd = sanitize_command(cmd)
    actual_sudo = sudo or "sudo" in cmd
    risk = analyze_risk(cmd)

    if risk == "critical":
        console.print("[bold red]CRITICAL SECURITY WARNING[/bold red]")

    if sudo and not cmd.startswith("sudo"):
        cmd = f"sudo -E {cmd}"

    console.print(f"\n[bold green]>[/bold green] {'[bold red]SUDO[/] ' if actual_sudo else ''}[command]{cmd}[/command]")

    if risk == "critical" or actual_sudo:
        if not sys.stdin.isatty(): raise UserAbort("High risk command denied.")
        if input(f"\033[33mExecute?\033[0m (y/n): ").lower() not in ["y", "yes"]:
            raise UserAbort("Action denied.")

    forbidden = ["nano", "vim", "vi", "htop", "less", "more", "watch", "telnet"]
    if any(f" {t}" in cmd for t in forbidden) or cmd.startswith(tuple(forbidden)):
        return "Error: Interactive tools blocked."

    if actual_sudo:
        if subprocess.run("sudo -n true", shell=True).returncode != 0:
            console.print("[dim yellow]Sudo authentication required...[/dim yellow]")
            subprocess.run("sudo -v", shell=True)

    safe_env = os.environ.copy()
    safe_env.update({"PAGER": "cat", "SYSTEMD_PAGER": "cat", "TERM": "dumb"})

    try:
        # Only use spinner if NOT debugging, to avoid hiding debug logs
        if not DEBUG:
            with console.status("[dim]Running...[/dim]", spinner="dots"):
                result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT,
                                        env=safe_env)
        else:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT,
                                    env=safe_env)

        output = result.stdout + result.stderr
        return truncate_output(output.strip() or "Success (No Output)")
    except Exception as e:
        return f"Error: {e}"


@tool
def run_remote_command(command: str, host: str, user: str = "admin", sudo: bool = False) -> str:
    """Executes a command on a remote server via SSH."""
    command = sanitize_command(command.strip())
    if sudo and not command.startswith("sudo"): command = f"sudo -E -n {command}"

    risk = analyze_risk(command)
    if risk == "critical": console.print("[bold red]CRITICAL SECURITY WARNING[/bold red]")
    console.print(f"\n[bold cyan]>[/bold cyan] [dim]Remote ({user}@{host}):[/dim] [command]{command}[/command]")

    if risk == "critical" or (sudo or "sudo" in command):
        if not sys.stdin.isatty(): raise UserAbort("High risk command denied.")
        if input(f"\033[33mExecute Remote?\033[0m (y/n): ").lower() not in ["y", "yes"]:
            raise UserAbort("Action denied.")

    cmd_with_env = f"export PAGER=cat SYSTEMD_PAGER=cat TERM=dumb; {command}"
    ssh_opts = f"-o BatchMode=yes -o ConnectTimeout={SSH_CONN_TIMEOUT} -o StrictHostKeyChecking=accept-new"
    full_ssh_cmd = f"ssh {ssh_opts} {user}@{host} {shlex.quote(cmd_with_env)}"

    try:
        if not DEBUG:
            with console.status(f"[dim]Connecting to {host}...[/dim]", spinner="earth"):
                result = subprocess.run(full_ssh_cmd, shell=True, text=True, capture_output=True, timeout=30)
        else:
            result = subprocess.run(full_ssh_cmd, shell=True, text=True, capture_output=True, timeout=30)

        output = result.stdout + result.stderr
        if result.returncode == 255: return f"SSH Connection Failed: {output.strip()}"
        return truncate_output(output.strip() or "Success (No Output)")
    except Exception as e:
        return f"Error: {e}"


@tool
def write_file(file_path: str, content: str) -> str:
    """Writes text content to a file on the LOCAL machine."""
    try:
        path = os.path.expanduser(file_path)
        if path.startswith(("/etc", "/boot", "/usr", "/var/lib")):
            return "Error: Writing to system directories is forbidden."
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"[bold green]File Written:[/bold green] {path}")
        return f"Success: File wrote to {path}"
    except Exception as e:
        return f"Error: {e}"


@tool
def read_file(file_path: str) -> str:
    """Reads the content of a file from the LOCAL machine."""
    try:
        path = os.path.expanduser(file_path)
        if not os.path.exists(path): return f"Error: File not found: {path}"
        if os.path.getsize(path) > 5_000_000 and not DEBUG:
            return "Error: File too large (>5MB)."
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            console.print(f"[dim]ðŸ“„ Read file: {path}[/dim]")
            return truncate_output(f.read())
    except Exception as e:
        return f"Error: {e}"


# --- LLM & AGENT ---
llm = ChatOllama(model=MODEL, temperature=0.1, num_ctx=CTX_LENGTH, keep_alive=OLLAMA_KEEPALIVE)

system_prompt_agent = SystemMessage(content="""
You are STELLA.
1. Plan briefly.
2. Execute locally ('run_linux_command', 'read_file', 'write_file') or remotely ('run_remote_command').
   -Managed host information is located in the file: /home/administrator/managed_hosts.json. Use that for reference if no information provided
3. Summarize findings.
CRITICAL: Remote commands are stateless. Use 'write_file' for complex logic/scripts.
""")

agent = create_agent(
    model=llm,
    tools=[run_linux_command, run_remote_command, write_file, read_file],
    system_prompt=system_prompt_agent,
)

# --- EXECUTION ENTRY POINT ---
if __name__ == "__main__":
    if sys.stdin.isatty() or DEBUG:
        wait_for_model_load(llm)
    else:
        try:
            llm.invoke("Hi")
        except:
            sys.exit(1)

    # 1. Piped Input
    if not sys.stdin.isatty():
        content = truncate_output(sys.stdin.read().strip())
        prompt = f"Context:\n{content}\n\nInstruction: {' '.join(args.prompt)}"
        console.print(
            Markdown(llm.invoke([SystemMessage(content="Analyze this."), HumanMessage(content=prompt)]).content))
        sys.exit(0)

    # 2. Single Command
    if args.prompt:
        try:
            res = agent.invoke({"messages": [HumanMessage(content=" ".join(args.prompt))]},
                               config={"callbacks": [SpinnerHandler(console)]})
            console.print(Markdown(res['messages'][-1].content))
        except (UserAbort, KeyboardInterrupt):
            console.print("[yellow]Aborted.[/yellow]")
        sys.exit(0)

    # 3. Interactive
    console.print(f"[bold green]STELLA ({MODEL})[/bold green] [dim]Ready.[/dim]")
    session = PromptSession(history=InMemoryHistory())
    messages = []

    while True:
        try:
            user_input = session.prompt(HTML("\n<b><green>>></green></b> "))
            if user_input.lower() in ["exit", "quit", "bye"]: break

            # Context sliding window
            if len(messages) > MAX_HISTORY: messages = messages[-MAX_HISTORY:]

            messages.append(HumanMessage(content=user_input))
            response = agent.invoke({"messages": messages}, config={"callbacks": [SpinnerHandler(console)]})
            messages = response['messages']
            console.print()
            console.print(Markdown(messages[-1].content))

        except KeyboardInterrupt:
            break
        except UserAbort:
            console.print("[yellow]Aborted.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
