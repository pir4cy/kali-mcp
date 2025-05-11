from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP, Context, Image
import os
import asyncio
import logging
import json
from pathlib import Path
from utils.output_analyzer import analyze_output
from utils.command_builder import build_command
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kali-mcp')

logger.info("MCP server is starting up!")
print("MCP server is starting up! (print)")

# Create MCP server
mcp = FastMCP(
    name="KaliMCP",
    description="Cybersecurity research assistant running Kali Linux tools",
    dependencies=["pexpect", "colorama", "python-dotenv"]
)

# Store running tools and their status
running_processes = {}

# Define tool categories
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

# At the top of your file
available_tools_global = {
    "reconnaissance": ["nmap", "whois"],
    "vulnerability": ["nikto"],
}

# Server lifecycle management
@asynccontextmanager
async def server_lifespan(server):
    logger.info("DEBUG: Entered server_lifespan")
    # Check for Kali Linux
    try:
        with open("/etc/os-release", "r") as f:
            if "kali" not in f.read().lower():
                logger.warning("Not running on Kali Linux. Some tools may not be available.")
    except:
        logger.warning("Could not determine OS. Assuming non-Kali environment.")
    
    # Check for tool availability
    available_tools = {}
    logger.info("DEBUG: PATH seen by server is %s", os.environ.get("PATH"))
    logger.info("DEBUG: shutil.which('nmap') = %s", shutil.which('nmap'))
    for category, tools in TOOL_CATEGORIES.items():
        available_tools[category] = []
        for tool in tools:
            tool_path = shutil.which(tool)
            logger.info("DEBUG: checking tool %s, found at %s", tool, tool_path)
            if tool_path is not None:
                available_tools[category].append(tool)
                
    logger.info("Available tools: %s", json.dumps(available_tools, indent=2))
    
    # global available_tools_global
    # available_tools_global = available_tools
    logger.info("DEBUG: available_tools_global set to %s", available_tools_global)
    yield {"available_tools": available_tools}
    
    # Clean up any running processes
    for pid in list(running_processes.keys()):
        try:
            process = running_processes[pid]["process"]
            process.kill()
            logger.info(f"Terminated process {pid}")
        except:
            pass

# Use the lifespan manager
mcp.lifespan = server_lifespan

@mcp.resource("tools://categories")
def get_tool_categories() -> str:
    """Get all available tool categories"""
    global available_tools_global
    available_tools = available_tools_global
    result = "# Available Kali Tool Categories\n\n"
    
    for category, tools in available_tools.items():
        if tools:  # Only include categories with available tools
            result += f"## {category.title()}\n"
            for tool in tools:
                result += f"- {tool}\n"
            result += "\n"
    
    return result

def get_available_tools():
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
    return available

@mcp.tool()
async def run_tool(ctx: Context, tool_name: str, arguments: str = "", analysis: str = "concise") -> str:
    """
    Run a Kali Linux security tool with the specified arguments
    """
    available_tools = get_available_tools()
    # Flatten available tools for lookup
    all_tools = []
    for category_tools in available_tools.values():
        all_tools.extend(category_tools)
    if tool_name not in all_tools:
        return f"Error: Tool '{tool_name}' is not available. Use 'discover_tools' to see available tools."
    # Build and validate command
    cmd = build_command(tool_name, arguments)
    if not cmd:
        return f"Error: Invalid command or arguments for {tool_name}"
    ctx.info(f"Running: {cmd}")
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    pid = process.pid
    running_processes[pid] = {
        "process": process,
        "command": cmd,
        "tool": tool_name
    }
    ctx.info(f"Process started with PID {pid}")
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        stdout = stdout.decode('utf-8', errors='replace')
        stderr = stderr.decode('utf-8', errors='replace')
        return_code = process.returncode
    except asyncio.TimeoutError:
        process.kill()
        return "Error: Command timed out after 5 minutes"
    if pid in running_processes:
        del running_processes[pid]
    output = stdout
    if stderr and return_code != 0:
        output = f"STDERR:\n{stderr}\n\nSTDOUT:\n{stdout}"
    if analysis.lower() != "none":
        return analyze_output(tool_name, output, analysis.lower())
    return output

@mcp.tool()
async def discover_tools(ctx: Context, category: str = None, keyword: str = None) -> str:
    """
    Find Kali tools by category or keyword
    """
    available_tools = get_available_tools()
    if not available_tools:
        return "Error: No available tools found."
    if not category and not keyword:
        return "Please specify either a category or a keyword to search for tools."
    results = []
    if category:
        if category.lower() not in available_tools:
            categories = ", ".join(available_tools.keys())
            return f"Category '{category}' not found. Available categories: {categories}"
        tools = available_tools[category.lower()]
        results.extend(tools)
    if keyword:
        keyword = keyword.lower()
        for cat, tools in available_tools.items():
            for tool in tools:
                if keyword in tool.lower() and tool not in results:
                    results.append(tool)
    if not results:
        return "No matching tools found."
    output = f"Found {len(results)} tools:\n\n"
    for tool in sorted(results):
        desc_process = await asyncio.create_subprocess_shell(
            f"whatis {tool} 2>/dev/null || echo '{tool}: No description available'",
            stdout=asyncio.subprocess.PIPE
        )
        desc, _ = await desc_process.communicate()
        desc = desc.decode('utf-8', errors='replace').strip()
        output += f"- {desc}\n"
    return output

@mcp.tool()
async def analyze_screenshot(ctx: Context, target: str = None, save_path: str = None, tool: str = "scrot") -> Image:
    """
    Take a screenshot and analyze it for security issues
    
    Args:
        target: What to capture (full, window, selection)
        save_path: Where to save the screenshot
        tool: Screenshot tool to use (scrot or flameshot)
    """
    if tool not in ["scrot", "flameshot"]:
        return "Error: Only scrot and flameshot are supported"
    
    # Default path if not provided
    if not save_path:
        save_path = f"/tmp/kali_mcp_screenshot_{int(asyncio.time())}.png"
    
    # Build command based on tool choice
    if tool == "scrot":
        cmd = f"scrot"
        if target == "window":
            cmd += " --focused"
        elif target == "selection":
            cmd += " --select"
        cmd += f" {save_path}"
    else:  # flameshot
        cmd = f"flameshot"
        if target == "full":
            cmd += " full"
        elif target == "selection":
            cmd += " gui"
        cmd += f" -p {save_path}"
    
    # Execute command
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    await process.communicate()
    
    if process.returncode != 0:
        return f"Error: Failed to take screenshot with {tool}"
    
    # Read image file
    try:
        with open(save_path, "rb") as f:
            image_data = f.read()
        
        # Return image with analysis
        return Image(data=image_data, format="png")
    except Exception as e:
        return f"Error reading screenshot: {str(e)}"

@mcp.prompt()
def scan_target(target: str) -> str:
    """Scan a target for vulnerabilities"""
    return f"""I need to perform security reconnaissance on the target: {target}

Please help me by:
1. Running an initial nmap scan to discover open ports
2. Analyzing the results to identify potential vulnerabilities 
3. Suggesting next steps for further investigation
"""

@mcp.prompt()
def analyze_pcap(pcap_file: str) -> str:
    """Analyze a packet capture file"""
    return f"""I need to analyze this network capture file: {pcap_file}

Could you help me:
1. Use appropriate Kali tools to extract key information
2. Identify any suspicious network traffic
3. Highlight potential security concerns
4. Recommend further analysis steps
"""

if __name__ == "__main__":
    mcp.run()