import shutil
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("TestServer")

@mcp.tool()
def echo(msg: str) -> str:
    return f"Echo: {msg}"

@mcp.tool()
def kali_tool_paths() -> str:
    TOOL_CATEGORIES = {
        "reconnaissance": ["nmap", "whois", "dig", "host", "theHarvester", "recon-ng"],
        "vulnerability": ["nikto", "wpscan", "sqlmap", "owasp-zap", "openvas", "nuclei"],
        "exploitation": ["metasploit", "exploitdb", "searchsploit", "setoolkit", "beef-xss"],
        "wireless": ["aircrack-ng", "wifite", "kismet", "reaver", "bully", "wifiphisher"],
        "web": ["burpsuite", "dirb", "gobuster", "ffuf", "wfuzz", "hydra"],
        "forensics": ["volatility", "autopsy", "binwalk", "foremost", "bulk_extractor"],
        "cryptography": ["hashcat", "john", "gpg", "openssl", "hashid"],
        "sniffing": ["wireshark", "tcpdump", "ettercap", "bettercap", "dsniff"]
    }
    result = "# Kali Tool Paths\n\n"
    for category, tools in TOOL_CATEGORIES.items():
        result += f"## {category.title()}\n"
        for tool in tools:
            path = shutil.which(tool)
            result += f"- {tool}: {path}\n"
        result += "\n"
    return result

@mcp.tool()
def discover_tools() -> str:
    TOOL_CATEGORIES = {
        "reconnaissance": ["nmap", "whois", "dig", "host", "theHarvester", "recon-ng"],
        "vulnerability": ["nikto", "wpscan", "sqlmap", "owasp-zap", "openvas", "nuclei"],
        "exploitation": ["metasploit", "exploitdb", "searchsploit", "setoolkit", "beef-xss"],
        "wireless": ["aircrack-ng", "wifite", "kismet", "reaver", "bully", "wifiphisher"],
        "web": ["burpsuite", "dirb", "gobuster", "ffuf", "wfuzz", "hydra"],
        "forensics": ["volatility", "autopsy", "binwalk", "foremost", "bulk_extractor"],
        "cryptography": ["hashcat", "john", "gpg", "openssl", "hashid"],
        "sniffing": ["wireshark", "tcpdump", "ettercap", "bettercap", "dsniff"]
    }
    available = {}
    for category, tools in TOOL_CATEGORIES.items():
        found = [tool for tool in tools if shutil.which(tool)]
        if found:
            available[category] = found
    if not available:
        return "No available tools found."
    result = "# Available Kali Tools\n\n"
    for category, tools in available.items():
        result += f"## {category.title()}\n"
        for tool in tools:
            result += f"- {tool}\n"
        result += "\n"
    return result

@mcp.tool()
def nmap_scan(target: str, arguments: str = "-T4 -F") -> str:
    cmd = f"nmap {arguments} {target}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output
    except Exception as e:
        return f"Error running nmap: {e}"

@mcp.tool()
def run_tool(tool_name: str, arguments: str = "") -> str:
    # All tools from main.py
    TOOL_CATEGORIES = {
        "reconnaissance": ["nmap", "whois", "dig", "host", "theHarvester", "recon-ng"],
        "vulnerability": ["nikto", "wpscan", "sqlmap", "owasp-zap", "openvas", "nuclei"],
        "exploitation": ["metasploit", "exploitdb", "searchsploit", "setoolkit", "beef-xss"],
        "wireless": ["aircrack-ng", "wifite", "kismet", "reaver", "bully", "wifiphisher"],
        "web": ["burpsuite", "dirb", "gobuster", "ffuf", "wfuzz", "hydra", "cutycapt"],
        "forensics": ["volatility", "autopsy", "binwalk", "foremost", "bulk_extractor"],
        "cryptography": ["hashcat", "john", "gpg", "openssl", "hashid"],
        "sniffing": ["wireshark", "tcpdump", "ettercap", "bettercap", "dsniff"],
        "screenshot": ["scrot", "maim", "screenshot", "flameshot"]
    }
    # Flatten available tools
    all_tools = set()
    for tools in TOOL_CATEGORIES.values():
        all_tools.update(tools)
    if tool_name not in all_tools:
        return f"Error: Tool '{tool_name}' is not recognized."
    if not shutil.which(tool_name):
        return f"Error: Tool '{tool_name}' is not installed or not in PATH."
    cmd = f"{tool_name} {arguments}".strip()
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output
    except Exception as e:
        return f"Error running {tool_name}: {e}"

@mcp.tool()
def install_all_kali_tools() -> str:
    TOOL_CATEGORIES = {
        "reconnaissance": ["nmap", "whois", "dig", "host", "theHarvester", "recon-ng"],
        "vulnerability": ["nikto", "wpscan", "sqlmap", "owasp-zap", "openvas", "nuclei"],
        "exploitation": ["metasploit", "exploitdb", "searchsploit", "setoolkit", "beef-xss"],
        "wireless": ["aircrack-ng", "wifite", "kismet", "reaver", "bully", "wifiphisher"],
        "web": ["burpsuite", "dirb", "gobuster", "ffuf", "wfuzz", "hydra"],
        "forensics": ["volatility", "autopsy", "binwalk", "foremost", "bulk_extractor"],
        "cryptography": ["hashcat", "john", "gpg", "openssl", "hashid"],
        "sniffing": ["wireshark", "tcpdump", "ettercap", "bettercap", "dsniff"]
    }
    all_tools = set()
    for tools in TOOL_CATEGORIES.values():
        all_tools.update(tools)
    cmd = "sudo apt-get update && sudo apt-get install -y " + " ".join(sorted(all_tools))
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
        output = result.stdout
        if result.stderr:
            output += f"\nSTDERR:\n{result.stderr}"
        return output
    except Exception as e:
        return f"Error installing tools: {e}"

@mcp.tool()
def web_screenshot(url: str, output: str = "screenshot.png") -> str:
    if not shutil.which("cutycapt"):
        return "Error: cutycapt is not installed."
    cmd = f"cutycapt --url={url} --out={output}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return f"Screenshot saved to {output}"
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Error running cutycapt: {e}"

if __name__ == "__main__":
    mcp.run()