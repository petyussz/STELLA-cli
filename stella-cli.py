#!/mnt/archive/venvs/langchain/bin/python

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

# --- PROMPT TOOLKIT (HISTORY & NAVIGATION) ---
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
    """Custom exception to stop agent execution immediately upon user denial."""
    pass

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="STELLA Linux Agent")
parser.add_argument("--model", type=str, default="ministral-3:8b", help="Ollama model to use")
parser.add_argument("--debug", action="store_true", help="Show raw reasoning and subprocess output")
parser.add_argument("--ctx", type=str, default="4096", help="Context length for the model")
parser.add_argument("prompt", nargs="*", help="Direct prompt for non-interactive mode")
args = parser.parse_args()

# --- CONFIGURATION ---
MODEL = args.model
MAX_HISTORY = 50
CTX_LENGTH = int(args.ctx)
SUBPROCESS_TIMEOUT = 30
SSH_CONN_TIMEOUT=10
WGET_CURL_TIMEOUT=60

# --- SPINNER HANDLER ---
class SpinnerHandler(BaseCallbackHandler):
    """
    Handles the spinner automatically based on LLM state.
    Starts when thinking, stops when tool execution begins (to allow input).
    """
    def __init__(self, console):
        self.console = console
        self.status = None

    def on_llm_start(self, serialized, prompts, **kwargs):
        self.status = self.console.status("[dim]Thinking...[/dim]", spinner="dots")
        self.status.start()

    def on_llm_end(self, response, **kwargs):
        if self.status:
            self.status.stop()

    def on_llm_error(self, error, **kwargs):
        if self.status:
            self.status.stop()

# --- HELPER FUNCTIONS ---

def truncate_output(text: str) -> str:
    """
    Smartly truncates output to keep the Head (beginning) and Tail (end).
    Crucial for reading logs where the most important info is at the bottom.
    """
    MAX_CHARS = int(CTX_LENGTH * 3) 
    
    if len(text) <= MAX_CHARS:
        return text
    
    half = MAX_CHARS // 2
    head = text[:half]
    tail = text[-half:]
    
    return f"{head}\n\n... [TRUNCATED {len(text) - MAX_CHARS} CHARS] ...\n\n{tail}"

def sanitize_command(cmd: str) -> str:
    """
    Sanitizes commands for safety and clarity.
    1. Enforces Sudo -E (Preserve Env) so PAGER=cat works as root.
    2. Enforces Systemctl -l (Full Length) to prevent text cutting.
    3. Enforces Curl/Wget Timeouts (Safety).
    """
    CONN_TIMEOUT = WGET_CURL_TIMEOUT
    cmd = cmd.strip()

    # Rule 1: Sudo -E Enforcement
    # We must preserve env vars (PAGER=cat) even when switching users.
    if re.search(r"\bsudo\b", cmd):
        # If -E is not present immediately after sudo, inject it.
        # This regex replaces 'sudo' with 'sudo -E' if -E isn't already there.
        # Note: This is a safe approximation.
        if "-E" not in cmd:
            cmd = re.sub(r"\bsudo\b", "sudo -E", cmd)

    # Rule 2: Systemctl
    # PAGER=cat prevents hanging, but systemctl still truncates lines without -l.
    if re.search(r"\bsystemctl\b", cmd):
        if not re.search(r" -l\b| --full\b", cmd):
            cmd = re.sub(r"\bsystemctl\b", "systemctl -l", cmd, count=1)

    # Rule 3: Curl Timeout
    if re.search(r"\bcurl\b", cmd):
        if not re.search(r"(--max-time|-m)\s+\d+", cmd):
            cmd = re.sub(r"\bcurl\b", f"curl --max-time {CONN_TIMEOUT}", cmd, count=1)

    # Rule 4: Wget Timeout
    if re.search(r"\bwget\b", cmd):
        if not re.search(r"(--timeout|-T)[=\s]+\d+", cmd):
            cmd = re.sub(r"\bwget\b", f"wget --timeout={CONN_TIMEOUT}", cmd, count=1)

    return cmd

def analyze_risk(cmd: str) -> str:
    """
    Analyzes command safety using shlex tokenization.
    Returns 'critical' or 'low'.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        console.print("[dim red]Warning: Command parsing failed (unbalanced quotes). Treating as Critical.[/dim red]")
        return "critical"

    commands_to_check = []
    
    if tokens:
        commands_to_check.append(tokens[0])
    
    for i, token in enumerate(tokens):
        if token == "|" and i + 1 < len(tokens):
            commands_to_check.append(tokens[i+1])
        # Handle sudo: if command is sudo, the NEXT word is the actual verb
        if token in ["sudo", "sudo -E"] and i + 1 < len(tokens):
            commands_to_check.append(tokens[i+1])

    CRITICAL_BINARIES = {
        "mkfs", "dd", "shutdown", "reboot", "init", 
        "chmod", "chown", "wget", "curl", "mv", "cp"
    }

    for cmd_verb in commands_to_check:
        if cmd_verb in CRITICAL_BINARIES:
            return "critical"
        
        if cmd_verb == "rm":
            if any(flag in tokens for flag in ["-r", "-R", "-rf", "-fr"]):
                return "critical"

    if ">" in tokens:
        idx = tokens.index(">")
        if idx + 1 < len(tokens):
            target = tokens[idx+1]
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

# --- TOOLS DEFINITION ---

@tool
def run_linux_command(cmd: str, sudo: bool = False) -> str:
    """
    Executes a LOCAL Linux shell command.
    """
    cmd = cmd.strip()

    # --- 1. Directory Persistence ---
    if cmd.startswith("cd "):
        try:
            target_dir = cmd[3:].strip()
            target_dir = os.path.expanduser(target_dir)
            os.chdir(target_dir)
            console.print(f"[dim]ðŸ“‚ CWD: {os.getcwd()}[/dim]")
            return f"Success: Changed directory to {os.getcwd()}"
        except Exception as e:
            return f"Error changing directory: {e}"

    # --- 2. Sanitize (Timeouts, Sudo -E, Systemctl -l) ---
    cmd = sanitize_command(cmd)

    # --- 3. Safety Analysis ---
    actual_sudo = sudo or "sudo" in cmd
    risk = analyze_risk(cmd)

    if risk == "critical":
        console.print("[bold red]CRITICAL SECURITY WARNING[/bold red]")

    # --- 4. Sudo Argument Injection ---
    # If the tool call explicitly requests sudo, inject "sudo -E"
    if sudo and not cmd.startswith("sudo"):
        cmd = f"sudo -E {cmd}"

    sudo_label = "[bold red]SUDO[/] " if actual_sudo else ""
    console.print(f"\n[bold green]>[/bold green] {sudo_label}[command]{cmd}[/command]")
    
    # --- 5. Confirmation ---
    if risk == "critical" or actual_sudo:
        if not sys.stdin.isatty():
             raise UserAbort("High risk command denied (Non-interactive mode).")
        
        confirm = input(f"\033[33mExecute?\033[0m (y/n): ")
        if confirm.lower() not in ["y", "yes"]:
            raise UserAbort("Action denied by user.")

    forbidden = ["nano", "vim", "vi", "htop", "less", "more", "watch", "nvtop", "ptop", "telnet"] 
    if any(f" {t}" in cmd for t in forbidden) or cmd.startswith(tuple(forbidden)):
        return "Error: Interactive tools (vim, top, etc) are blocked."

    # --- 6. Sudo Authentication ---
    if actual_sudo:
        # Check if we have tokens. We use 'sudo -n true' to check non-interactive status.
        sudo_check = subprocess.run("sudo -n true", shell=True, capture_output=True)
        if sudo_check.returncode != 0:
            console.print("[dim yellow]Sudo authentication required...[/dim yellow]")
            try:
                auth_result = subprocess.run("sudo -v", shell=True)
                if auth_result.returncode != 0:
                    return "Error: Sudo authentication failed or cancelled."
                console.print("[dim green]Authentication cached.[/dim green]")
            except Exception as e:
                return f"Error during sudo authentication: {e}"

    # --- 7. Execution with Safe Env ---
    # We construct a specific environment for this subprocess to force non-interactive behavior
    safe_env = os.environ.copy()
    safe_env["PAGER"] = "cat"
    safe_env["SYSTEMD_PAGER"] = "cat"
    safe_env["TERM"] = "dumb"  # Prevents some programs from using advanced terminal features

    with console.status("[dim]Running...[/dim]", spinner="dots"):
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                text=True, 
                capture_output=True, 
                timeout=SUBPROCESS_TIMEOUT,
                env=safe_env # <--- Inject Safe Env
            )
            output = result.stdout + result.stderr
            return truncate_output(output.strip() or "Success (No Output)")

        except subprocess.TimeoutExpired:
            return "Error: Command timed out."
        except Exception as e:
            return f"Error: {e}"

@tool
def run_remote_command(command: str, host: str, user: str = "admin", sudo: bool = False) -> str:
    """
    Executes a command on a remote server via SSH. 
    """
    command = command.strip()
    
    # --- 1. Sanitize (Timeouts, Sudo -E, Systemctl -l) ---
    command = sanitize_command(command)
    
    # --- 2. Sudo Argument Injection ---
    if sudo and not command.startswith("sudo"):
        command = f"sudo -E -n {command}" # -n for non-interactive

    actual_sudo = sudo or "sudo" in command
    risk = analyze_risk(command)

    if risk == "critical":
        console.print("[bold red]CRITICAL SECURITY WARNING[/bold red]")

    console.print(f"\n[bold cyan]>[/bold cyan] [dim]Remote ({user}@{host}):[/dim] [command]{command}[/command]")

    # --- 3. Confirmation ---
    if risk == "critical" or actual_sudo:
        if not sys.stdin.isatty():
             raise UserAbort("High risk command denied (Non-interactive mode).")
        
        confirm = input(f"\033[33mExecute Remote?\033[0m (y/n): ")
        if confirm.lower() not in ["y", "yes"]:
            raise UserAbort("Action denied by user.")

    # --- 4. Env Injection for Remote ---
    # Since we can't pass `env=` to SSH easily, we export them in the command string.
    # We use 'export' so they persist if the user chains commands (cmd1 && cmd2).
    # NOTE: sudo -E (added in sanitize step) ensures these survive the root switch.
    cmd_with_env = f"export PAGER=cat; export SYSTEMD_PAGER=cat; {command}"

    # --- 5. SSH Execution ---
    ssh_opts = f"-o BatchMode=yes -o ConnectTimeout={SSH_CONN_TIMEOUT} -o StrictHostKeyChecking=accept-new"
    full_ssh_cmd = f"ssh {ssh_opts} {user}@{host} {shlex.quote(cmd_with_env)}"

    with console.status(f"[dim]Connecting to {host}...[/dim]", spinner="earth"):
        try:
            result = subprocess.run(
                full_ssh_cmd, shell=True, text=True, capture_output=True, timeout=30 
            )
            output = result.stdout + result.stderr
            if result.returncode == 255:
                return f"SSH Connection Failed: {output.strip()}"
            return truncate_output(output.strip() or "Success (No Output)")

        except subprocess.TimeoutExpired:
            return "Error: Connection timed out."
        except Exception as e:
            return f"Error: {e}"

@tool
def write_file(file_path: str, content: str) -> str:
    """Writes text content to a file on the LOCAL machine."""
    try:
        target_path = os.path.expanduser(file_path)
        if target_path.startswith(("/etc", "/boot", "/usr", "/var/lib")):
            return "Error: Writing to system directories is forbidden."
        
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        console.print(f"[bold green]File Written:[/bold green] {target_path}")
        return f"Success: File wrote to {target_path}"

    except Exception as e:
        return f"Error writing file: {e}"

@tool
def read_file(file_path: str) -> str:
    """Reads the content of a file from the LOCAL machine."""
    try:
        target_path = os.path.expanduser(file_path)
        if not os.path.exists(target_path):
            return f"Error: File not found: {target_path}"
        
        if os.path.getsize(target_path) > 5_000_000:
            return "Error: File is too large (>5MB). Use run_linux_command with grep/head."

        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            
        console.print(f"[dim]ðŸ“„ Read file: {target_path}[/dim]")
        return truncate_output(content)

    except Exception as e:
        return f"Error reading file: {e}"

# --- LLM SETUP ---
llm = ChatOllama(
    model=MODEL,
    temperature=0.1,
    num_ctx=CTX_LENGTH,
)

# --- AGENT SETUP ---
system_prompt_agent = SystemMessage(
    content="""
You are STELLA.
1. Plan briefly.
2. Execute locally ('run_linux_command', 'read_file', 'write_file') or remotely ('run_remote_command').
   -Managed host information is located in the file: /home/administrator/managed_hosts.json. Use that for reference if no information provided
3. Summarize findings.
4. Use Markdown.

CRITICAL INSTRUCTIONS: 
- Remote commands are STATELESS. Chain them: "cd /opt/app && ./restart.sh".
- For complex logic (JSON parsing, loops), use 'write_file' to create a Python script, then run it.
- Do NOT use 'echo' or 'awk' to generate JSON strings in the shell (escaping issues).
"""
)

agent = create_agent(
    model=llm,
    tools=[run_linux_command, run_remote_command, write_file, read_file],
    system_prompt=system_prompt_agent,
)

# --- STARTUP ---
if sys.stdin.isatty() or args.debug:
    wait_for_model_load(llm)
else:
    try:
        llm.invoke("Hi")
    except:
        sys.exit(1)

# --- LOGIC BRANCHING ---

# 1. Piped Input -> PURE LLM
if not sys.stdin.isatty():
    stdin_content = sys.stdin.read().strip()
    cli_prompt = " ".join(args.prompt).strip()
    stdin_content = truncate_output(stdin_content)
    full_prompt = f"Context:\n{stdin_content}\n\nInstruction: {cli_prompt}" if cli_prompt else f"Analyze:\n{stdin_content}"
    
    try:
        response = llm.invoke([
            SystemMessage(content="You are a helpful Linux assistant. Provide clear analysis in Markdown."),
            HumanMessage(content=full_prompt)
        ])
        console.print(Markdown(response.content))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    sys.exit(0)

# 2. Argument Mode -> SINGLE SHOT AGENT
if args.prompt:
    prompt = " ".join(args.prompt).strip()
    try:
        response = agent.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"callbacks": [SpinnerHandler(console)]}
        )
        console.print()
        console.print(Markdown(response['messages'][-1].content))
    except UserAbort:
        console.print("\n[bold yellow]Operation aborted by user.[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    sys.exit(0)

# 3. Interactive Mode -> FULL SESSION
console.print(f"[bold green]STELLA ({MODEL})[/bold green] [dim]Ready.[/dim]")

session = PromptSession(history=InMemoryHistory())
messages = []
spinner_handler = SpinnerHandler(console)

while True:
    try:
        user_input = session.prompt(HTML("\n<b><green>>></green></b> "))

        if user_input.lower() in ["exit", "quit", "bye"]:
            break

        if len(messages) > MAX_HISTORY:
            messages = messages[-MAX_HISTORY:]
            while messages:
                if isinstance(messages[0], ToolMessage):
                    messages.pop(0)
                    continue
                break

        messages.append(HumanMessage(content=user_input))
        
        response = agent.invoke(
            {"messages": messages},
            config={"callbacks": [spinner_handler]}
        )

        new_messages = response['messages']
        messages = new_messages
        final_answer = messages[-1].content
        
        console.print()
        console.print(Markdown(final_answer))

    except KeyboardInterrupt:
        console.print("\n[bold red]Quit.[/bold red]")
        break
    except UserAbort:
        console.print("\n[bold yellow]Operation aborted by user.[/bold yellow]")
    except EOFError:
        break
    except Exception as e:
        console.print(f"[bold red]System Error:[/bold red] {e}")
