import subprocess
import os
import re
import sys
import argparse
from halo import Halo
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage, AIMessage
from langchain.agents import create_agent

# --- PROMPT TOOLKIT IMPORTS ---
from prompt_toolkit import prompt, PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.formatted_text import ANSI

# --- ARGUMENT PARSING ---
parser = argparse.ArgumentParser(description="STELLA Linux Agent")
parser.add_argument("--model", type=str, default="ministral-3:8b", help="Ollama model to use")
parser.add_argument("--debug", action="store_true", help="Show raw reasoning and subprocess output")
args = parser.parse_args()

# --- CONFIGURATION ---
MODEL = args.model
MAX_HISTORY = 50
CTX_LENGTH = 4096
SUBPROCESS_TIMEOUT = 30

# --- HELPER FUNCTIONS ---
def sanitize_command(cmd: str) -> str:
    CONN_TIMEOUT = 20  # seconds
    """
    Applies regex rules to fix dangerous, hanging, or runaway commands.
    """
    cmd = cmd.strip()

    # Rule 1: Prevent 'systemctl' hanging
    if re.search(r"\bsystemctl\b", cmd):
        if not re.search(r"--no-pager\s+.*--full|--full\s+.*--no-pager", cmd):
            cmd = re.sub(r"\bsystemctl\b", "systemctl --no-pager --full", cmd, count=1)

    # Rule 2: Prevent 'journalctl' hanging
    if re.search(r"\bjournalctl\b", cmd):
        if not re.search(r"--no-pager", cmd):
            cmd = re.sub(r"\bjournalctl\b", "journalctl --no-pager", cmd, count=1)

    # Rule 3: Prevent 'ssh' hanging
    if cmd.startswith("ssh "): 
        if "-o ConnectTimeout=" not in cmd:
            cmd = cmd.replace("ssh ", f"ssh -o ConnectTimeout={CONN_TIMEOUT} ", 1)

    # Rule 4: Prevent 'curl' hanging
    if re.search(r"\bcurl\b", cmd):
        if not re.search(r"(--max-time|-m)\s+\d+", cmd):
            cmd = re.sub(r"\bcurl\b", f"curl --max-time {CONN_TIMEOUT}", cmd, count=1)

    # Rule 5: Prevent 'wget' hanging 
    if re.search(r"\bwget\b", cmd):
        if not re.search(r"(--timeout|-T)[=\s]+\d+", cmd):
            cmd = re.sub(r"\bwget\b", f"wget --timeout={CONN_TIMEOUT}", cmd, count=1)

    return cmd

def wait_for_model_load(llm_instance):
    """
    Uses Halo to show a spinner while 'pinging' the model to force-load it.
    """
    spinner = Halo(text=f"Loading {llm_instance.model} into memory (Context: 16k)...", spinner='dots', color='cyan')
    spinner.start()

    try:
        # We invoke the specific LLM instance to ensure the correct context window is allocated
        llm_instance.invoke("Hi") 
        spinner.succeed(f"Model {llm_instance.model} loaded and ready!")
    except Exception as e:
        spinner.fail(f"Error loading model: {e}")
        print("\nEnsure Ollama is running (ollama serve).")
        sys.exit(1)

# --- TOOL DEFINITION ---
@tool
def run_linux_command(cmd: str, sudo: bool = False, risk: str = "low") -> str:
    """
    Executes a Linux shell command.

    Args:
        cmd: The bash command to run.
        sudo: True if root privileges are required.
        risk: low | medium | high | critical
    """

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    NC = "\033[0m"

    cmd = cmd.strip()

    # --- 1. Directory Persistence ---
    if cmd.startswith("cd "):
        try:
            target_dir = cmd[3:].strip()
            target_dir = os.path.expanduser(target_dir)
            os.chdir(target_dir)
            print(f"\n{BLUE}--- DIRECTORY CHANGED ---{NC}")
            print(f"NEW PATH: {os.getcwd()}")
            return f"Success: Changed directory to {os.getcwd()}"
        except Exception as e:
            return f"Error changing directory: {e}"

    # --- 2. Sanitize Command ---
    cmd = sanitize_command(cmd)

    # --- 3. Safety Analysis (Heuristic Enforcement) ---
    actual_sudo = sudo or "sudo" in cmd
    
    # Define patterns that are inherently critical regardless of what LLM thinks
    CRITICAL_PATTERNS = [
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*",   # Recursive removal (rm -rf, rm -r)
        r"\bmkfs",                        # Formatting filesystems
        r"\bdd\b",                        # Low-level data copy
        r">\s*/etc/",                     # Writing to /etc configuration
        r">\s*/boot/",                    # Writing to /boot
        r"\bchmod\s+777",                 # Dangerous permissions
        r"\bchown\b",                     # Ownership changes
        r"\breboot\b",                    # Reboot
        r"\bshutdown\b"                   # Shutdown
    ]

    # Heuristic override: Check if command matches critical patterns
    is_critical_match = any(re.search(pattern, cmd) for pattern in CRITICAL_PATTERNS)
    
    if is_critical_match:
        risk = "critical"
        print(f"\n{RED}!!! SECURITY OVERRIDE: CRITICAL COMMAND DETECTED !!!{NC}")

    c_sudo = RED if actual_sudo else GREEN
    c_risk = GREEN
    if risk.lower() in ["high", "critical"]:
        c_risk = RED
    elif risk.lower() == "medium":
        c_risk = YELLOW

    print(f"\n{BLUE}--- ACTION ANALYSIS ---{NC}")
    print(f"COMMAND: {cmd}")
    print(f"SUDO:    {c_sudo}{actual_sudo}{NC}")
    print(f"RISK:    {c_risk}{risk.upper()}{NC}")

    # Enforce confirmation if Sudo is used OR if risk is elevated
    if risk.lower() in ["medium", "high", "critical"] or actual_sudo:
        try:
            # REPLACEMENT: using prompt_toolkit's prompt with ANSI wrapper
            confirm = prompt(ANSI(f"{c_risk}⚠️  CONFIRM EXECUTION?{NC} (yes/no): "))
            if confirm.lower() != "yes":
                return "Action denied by user."
        except EOFError:
            return "Action denied."

    forbidden = ["nano", "vim", "vi", "htop", "less", "more", "watch", "nvtop", "ptop", "telnet"] 
    if any(f" {t}" in cmd for t in forbidden) or cmd.startswith(tuple(forbidden)):
        return "Error: Interactive tools (vim, top, etc) are blocked."

    # Prepend sudo if requested but missing
    if sudo and not cmd.startswith("sudo") and "|" not in cmd:
        cmd = f"sudo {cmd}"

    print(f"[EXECUTING]: \033[1;33m{cmd}\033[0m")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        
        # --- DEBUG: Raw Subprocess Output ---
        if args.debug:
            print(f"\n{MAGENTA}--- [DEBUG] RAW SUBPROCESS OUTPUT ---{NC}")
            print(f"{MAGENTA}STDOUT:{NC}\n{result.stdout}")
            if result.stderr:
                print(f"{MAGENTA}STDERR:{NC}\n{result.stderr}")
            print(f"{MAGENTA}-------------------------------------{NC}\n")

        output = result.stdout + result.stderr
        return output.strip() or "Success (No Output)"

    except subprocess.TimeoutExpired:
        return "Error: Command timed out (ran longer than 30s)."
    except Exception as e:
        return f"Error: {e}"

# --- LLM ---
llm = ChatOllama(
    model=MODEL,
    temperature=0.1,
    num_ctx=CTX_LENGTH,
)

# --- SYSTEM PROMPT (UPDATED FOR CoT) ---
# We now encourage the model to "Plan" (reasoning) before "Action".
system_prompt = SystemMessage(
    content="""
You are a local Linux System Administrator.
1. First, briefly explain your plan (Reasoning).
2. Then, call 'run_linux_command' to execute the plan.
3. Be concise. Analyze output and adjust if errors occur.
4. Always estimate 'sudo' (True if system state changes) and 'risk' correctly.
"""
)

# --- CREATE AGENT ---
agent = create_agent(
    model=llm,
    tools=[run_linux_command],
    system_prompt=system_prompt,
)

# --- STARTUP CHECK ---
wait_for_model_load(llm)

# --- MAIN LOOP ---
print(f"--- 🦜🔗 S.T.E.L.L.A Linux Agent ({MODEL}) ---")
print(f"--- Context Limit: Last {MAX_HISTORY} Messages ---")
if args.debug:
    print("\033[1;35m--- DEBUG MODE ENABLED ---\033[0m")
print("Type 'exit' or 'bye' to quit or press Ctrl+C.")

# Initialize Prompt Session for history support
session = PromptSession(history=InMemoryHistory())

messages = []

while True:
    try:
        # REPLACEMENT: using session.prompt with ANSI wrapper
        user_input = session.prompt(ANSI("\n\033[1;32mUser >>\033[0m "))

        if user_input.lower() in ["exit", "quit", "bye"]:
            print("Exiting...")
            break

        # --- Memory Management (Updated Slicing) ---
        if len(messages) > MAX_HISTORY:
            # 1. Hard slice
            messages = messages[-MAX_HISTORY:]
            
            # 2. Smart Trim: Ensure we don't start with a 'broken' tool chain
            # We remove messages from the start until we find a clean starting point (Human or complete AI message)
            while messages:
                first_msg = messages[0]
                
                # If it's a ToolMessage, it's an orphan output -> Remove it
                if isinstance(first_msg, ToolMessage):
                    messages.pop(0)
                    continue
                
                # If it's an AIMessage that calls tools, we need to ensure the previous context explains it. 
                # (Or strictly speaking, just ensure we don't start with a ToolMessage is usually enough for basic stability,
                # but if we start with an AI response that says "Here is the output" and the output is gone, it's confusing.)
                # For this implementation, removing orphan ToolMessages is the critical fix.
                break

        messages.append(HumanMessage(content=user_input))
        response = agent.invoke({"messages": messages})

        # Update messages with the agent's response chain
        new_messages = response['messages']
        
        # --- DEBUG: Show Model Reasoning / Intermediate Steps ---
        if args.debug:
            print(f"\n\033[1;35m--- [DEBUG] MODEL REASONING ---")
            start_index = len(messages) 
            for msg in new_messages[start_index:]:
                print(f"Type: {type(msg).__name__}")
                print(f"Content: {msg.content}")
                if hasattr(msg, 'tool_calls') and msg.tool_calls:
                    print(f"Tool Calls: {msg.tool_calls}")
            print(f"-------------------------------\033[0m")

        messages = new_messages
        final_answer = messages[-1].content
        print(f"\n\033[1;34mAgent:\033[0m {final_answer}")

    except KeyboardInterrupt:
        print("\n\nForce quit detected. Goodbye.")
        break

    except EOFError:
        print("\nExiting...")
        break

    except Exception as e:
        print(f"\nError: {e}")