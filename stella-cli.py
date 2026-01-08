import subprocess
import os
import re
import sys
import argparse
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_core.callbacks import BaseCallbackHandler
from langchain.agents import create_agent

# --- RICH UI IMPORTS ---
from rich.console import Console
from rich.markdown import Markdown
from rich.theme import Theme

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

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="STELLA Linux Agent")
parser.add_argument("--model", type=str, default="ministral-3:8b", help="Ollama model to use")
parser.add_argument("--debug", action="store_true", help="Show raw reasoning and subprocess output")
parser.add_argument("prompt", nargs="*", help="Direct prompt for non-interactive mode")
args = parser.parse_args()

# --- CONFIGURATION ---
MODEL = args.model
MAX_HISTORY = 50
CTX_LENGTH = 4096
SUBPROCESS_TIMEOUT = 30
HISTORY_FILE = os.path.expanduser("~/.stella_history") 

# --- SPINNER HANDLER (FIX FOR INPUT CONFLICT) ---
class SpinnerHandler(BaseCallbackHandler):
    """
    Handles the spinner automatically based on LLM state.
    Starts when thinking, stops when tool execution begins (to allow input).
    """
    def __init__(self, console):
        self.console = console
        self.status = None

    def on_llm_start(self, serialized, prompts, **kwargs):
        # Start spinner when LLM begins generating tokens
        self.status = self.console.status("[dim]Thinking...[/dim]", spinner="dots")
        self.status.start()

    def on_llm_end(self, response, **kwargs):
        # Stop spinner immediately when generation ends (before tool runs)
        if self.status:
            self.status.stop()

    def on_llm_error(self, error, **kwargs):
        if self.status:
            self.status.stop()

# --- HELPER FUNCTIONS ---
def sanitize_command(cmd: str) -> str:
    CONN_TIMEOUT = 20
    cmd = cmd.strip()

    # Rule 1: Systemctl
    if re.search(r"\bsystemctl\b", cmd):
        if not re.search(r"--no-pager\s+.*--full|--full\s+.*--no-pager", cmd):
            cmd = re.sub(r"\bsystemctl\b", "systemctl --no-pager --full", cmd, count=1)

    # Rule 2: Journalctl
    if re.search(r"\bjournalctl\b", cmd):
        if not re.search(r"--no-pager", cmd):
            cmd = re.sub(r"\bjournalctl\b", "journalctl --no-pager", cmd, count=1)

    # Rule 3: SSH
    if cmd.startswith("ssh "): 
        if "-o ConnectTimeout=" not in cmd:
            cmd = cmd.replace("ssh ", f"ssh -o ConnectTimeout={CONN_TIMEOUT} ", 1)

    # Rule 4: Curl
    if re.search(r"\bcurl\b", cmd):
        if not re.search(r"(--max-time|-m)\s+\d+", cmd):
            cmd = re.sub(r"\bcurl\b", f"curl --max-time {CONN_TIMEOUT}", cmd, count=1)

    # Rule 5: Wget
    if re.search(r"\bwget\b", cmd):
        if not re.search(r"(--timeout|-T)[=\s]+\d+", cmd):
            cmd = re.sub(r"\bwget\b", f"wget --timeout={CONN_TIMEOUT}", cmd, count=1)

    return cmd

def wait_for_model_load(llm_instance):
    with console.status(f"[dim]Loading {llm_instance.model}...[/dim]", spinner="dots"):
        try:
            llm_instance.invoke("Hi") 
        except Exception as e:
            console.print(f"[bold red]Error loading model: {e}[/bold red]")
            sys.exit(1)

# --- TOOL DEFINITION ---
@tool
def run_linux_command(cmd: str, sudo: bool = False, risk: str = "low") -> str:
    """
    Executes a Linux shell command.
    """
    cmd = cmd.strip()

    # --- 1. Directory Persistence ---
    if cmd.startswith("cd "):
        try:
            target_dir = cmd[3:].strip()
            target_dir = os.path.expanduser(target_dir)
            os.chdir(target_dir)
            console.print(f"[dim]📂 CWD: {os.getcwd()}[/dim]")
            return f"Success: Changed directory to {os.getcwd()}"
        except Exception as e:
            return f"Error changing directory: {e}"

    # --- 2. Sanitize ---
    cmd = sanitize_command(cmd)

    # --- 3. Safety Analysis ---
    actual_sudo = sudo or "sudo" in cmd
    
    CRITICAL_PATTERNS = [
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*", r"\bmkfs", r"\bdd\b", 
        r">\s*/etc/", r">\s*/boot/", r"\bchmod\s+777", 
        r"\bchown\b", r"\breboot\b", r"\bshutdown\b"
    ]

    if any(re.search(pattern, cmd) for pattern in CRITICAL_PATTERNS):
        risk = "critical"
        console.print("[bold red]CRITICAL SECURITY WARNING[/bold red]")

    # --- TEXT ONLY EXECUTION NOTIFICATION ---
    sudo_label = "[bold red]SUDO[/] " if actual_sudo else ""
    console.print(f"\n[bold green]>[/bold green] {sudo_label}[command]{cmd}[/command]")
    
    # --- CONFIRMATION ---
    if risk.lower() in ["medium", "high", "critical"] or actual_sudo:
        if not sys.stdin.isatty():
             return "Error: High risk command denied (Non-interactive mode)."
        
        # NOTE: Because the spinner is stopped via the Handler, input() works here now.
        confirm = input(f"\033[33mExecute?\033[0m (y/n): ")
        if confirm.lower() not in ["y", "yes"]:
            return "Action denied by user."

    forbidden = ["nano", "vim", "vi", "htop", "less", "more", "watch", "nvtop", "ptop", "telnet"] 
    if any(f" {t}" in cmd for t in forbidden) or cmd.startswith(tuple(forbidden)):
        return "Error: Interactive tools (vim, top, etc) are blocked."

    if sudo and not cmd.startswith("sudo") and "|" not in cmd:
        cmd = f"sudo {cmd}"

    # --- SUDO AUTHENTICATION HANDLER ---
    # If the command requires sudo, we must ensure we have a cached sudo token.
    # We run 'sudo -v' interactively so the user can type the password if needed.
    if actual_sudo:
        # check if we already have sudo rights without prompt
        sudo_check = subprocess.run("sudo -n true", shell=True, capture_output=True)
        if sudo_check.returncode != 0:
            console.print("[dim yellow]Sudo authentication required...[/dim yellow]")
            try:
                # Run sudo -v explicitly connecting streams to allow password input
                auth_result = subprocess.run("sudo -v", shell=True)
                if auth_result.returncode != 0:
                    return "Error: Sudo authentication failed or cancelled."
                console.print("[dim green]Authentication cached.[/dim green]")
            except Exception as e:
                return f"Error during sudo authentication: {e}"

    # Execution Spinner
    with console.status("[dim]Running...[/dim]", spinner="dots"):
        try:
            # Now run the actual command with capture_output=True.
            # Since we ran 'sudo -v' above, this should not prompt for a password.
            result = subprocess.run(
                cmd, shell=True, text=True, capture_output=True, timeout=SUBPROCESS_TIMEOUT
            )
            
            if args.debug:
                console.print(f"[dim]--- STDOUT ---[/dim]\n{result.stdout}")
                if result.stderr:
                    console.print(f"[dim]--- STDERR ---[/dim]\n{result.stderr}")

            output = result.stdout + result.stderr
            return output.strip() or "Success (No Output)"

        except subprocess.TimeoutExpired:
            return "Error: Command timed out."
        except Exception as e:
            return f"Error: {e}"

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
2. Execute with 'run_linux_command'.
3. Summarize findings.
4. Use text only Markdown.

CRITICAL INSTRUCTION: When calling 'run_linux_command', do NOT escape special characters like pipes (|), redirection (>), or quotes. Pass the raw command string exactly as it would be typed in a shell.
"""
)

agent = create_agent(
    model=llm,
    tools=[run_linux_command],
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
    
    full_prompt = ""
    if cli_prompt:
        full_prompt = f"Context:\n{stdin_content}\n\nInstruction: {cli_prompt}"
    else:
        full_prompt = f"Analyze the following output:\n{stdin_content}"

    messages = [
        SystemMessage(content="You are a helpful Linux assistant. Provide clear, concise analysis in Markdown."),
        HumanMessage(content=full_prompt)
    ]
    try:
        response = llm.invoke(messages)
        console.print(Markdown(response.content))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    sys.exit(0)

# 2. Argument Mode -> SINGLE SHOT AGENT
if args.prompt:
    prompt = " ".join(args.prompt).strip()
    try:
        # For single shot, we can just use the status context manager as simple confirmation isn't as critical
        # or we can use the handler. Let's use the handler for consistency.
        response = agent.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"callbacks": [SpinnerHandler(console)]}
        )
        console.print()
        console.print(Markdown(response['messages'][-1].content))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    sys.exit(0)

# 3. Interactive Mode -> FULL SESSION WITH HISTORY
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
        
        # Invoke agent with the SpinnerHandler callback
        # The Handler takes care of starting/stopping the spinner
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
    except EOFError:
        break
    except Exception as e:
        console.print(f"[bold red]System Error:[/bold red] {e}")
