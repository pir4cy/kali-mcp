# test-mcp-2.py
import shutil
import subprocess
import os
import tempfile
from pathlib import Path
import time
from mcp.server.fastmcp import FastMCP, Context, Image

# Initialize MCP server
mcp = FastMCP(
    name="KaliSecurityTools",
    description="MCP server for Kali Linux security tools organized by function"
)

# --- ENUMERATION TOOLS ---
@mcp.tool()
async def enumerate_target(
    ctx: Context, 
    target: str, 
    scan_type: str = "basic", 
    ports: str = "top-1000"
) -> str:
    """
    Run a comprehensive enumeration suite on the target
    
    Args:
        target: IP address or hostname to scan
        scan_type: Type of scan (basic, full, stealth)
        ports: Port range to scan (e.g., "top-1000", "1-65535", "22,80,443")
    """
    ctx.info(f"Starting enumeration of {target} with {scan_type} scan...")
    
    result = "# Target Enumeration Results\n\n"
    
    # 1. NMAP Scan
    try:
        nmap_args = "-T4"
        if scan_type == "basic":
            nmap_args += " -A"
        elif scan_type == "full":
            nmap_args += " -A -p-"
        elif scan_type == "stealth":
            nmap_args += " -sS -A"
            
        if ports != "top-1000" and ports != "1-65535":
            nmap_args += f" -p {ports}"
            
        ctx.info(f"Running nmap with args: {nmap_args}")
        nmap_cmd = f"nmap {nmap_args} {target}"
        nmap_result = subprocess.run(nmap_cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        result += f"## Nmap Network Scan\n\n```\n{nmap_result.stdout.strip()}\n```\n\n"
        
        # Quick summary of open ports
        open_ports = []
        for line in nmap_result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
        
        if open_ports:
            result += "### Open Ports Summary\n\n"
            for port in open_ports:
                result += f"- {port}\n"
            result += "\n"
    except subprocess.TimeoutExpired:
        result += "⚠️ Nmap scan timed out after 5 minutes\n\n"
    except Exception as e:
        result += f"⚠️ Nmap scan error: {str(e)}\n\n"
    
    # 2. Web Enumeration with gobuster (if port 80/443 is open)
    if any("80/tcp" in p for p in open_ports) or any("443/tcp" in p for p in open_ports):
        try:
            ctx.info("Detected web port, running directory enumeration...")
            
            protocol = "https" if any("443/tcp" in p for p in open_ports) else "http"
            gobuster_cmd = f"gobuster dir -u {protocol}://{target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q"
            
            gobuster_result = subprocess.run(gobuster_cmd, shell=True, capture_output=True, text=True, timeout=180)
            
            result += f"## Web Directory Enumeration (gobuster)\n\n```\n{gobuster_result.stdout.strip()}\n```\n\n"
        except subprocess.TimeoutExpired:
            result += "⚠️ Gobuster scan timed out after 3 minutes\n\n"
        except Exception as e:
            result += f"⚠️ Gobuster error: {str(e)}\n\n"
    
    # 3. SMB Enumeration (if port 445 is open)
    if any("445/tcp" in p for p in open_ports):
        try:
            ctx.info("Detected SMB port, enumerating shares...")
            
            smbclient_cmd = f"smbclient -L {target} -N"
            smb_result = subprocess.run(smbclient_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            result += f"## SMB Share Enumeration\n\n```\n{smb_result.stdout.strip()}\n"
            if smb_result.stderr:
                result += f"\n{smb_result.stderr.strip()}"
            result += "\n```\n\n"
        except subprocess.TimeoutExpired:
            result += "⚠️ SMB enumeration timed out after 1 minute\n\n"
        except Exception as e:
            result += f"⚠️ SMB enumeration error: {str(e)}\n\n"
    
    # Summary section
    result += "## Enumeration Summary\n\n"
    result += f"Target: {target}\n"
    result += f"Scan type: {scan_type}\n"
    
    if open_ports:
        result += f"Open ports found: {len(open_ports)}\n"
    else:
        result += "No open ports detected\n"
        
    return result

@mcp.tool()
async def web_screenshot(ctx: Context, url: str) -> Image:
    """
    Take a screenshot of a website using headless browsing
    
    Args:
        url: Website URL to screenshot
    """
    ctx.info(f"Taking screenshot of {url}...")
    
    # Check if cutycapt is available (lightweight headless browser tool)
    cutycapt_path = shutil.which("cutycapt")
    if not cutycapt_path:
        ctx.info("cutycapt not found, trying wkhtmltoimage...")
        wkhtmltoimage_path = shutil.which("wkhtmltoimage")
        if not wkhtmltoimage_path:
            return "Error: No headless browser tools found. Please install cutycapt or wkhtmltoimage."
    
    # Create temp file for screenshot
    temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    temp_file.close()
    screenshot_path = temp_file.name
    
    try:
        if cutycapt_path:
            cmd = f"cutycapt --url='{url}' --out='{screenshot_path}' --delay=3000"
        else:
            cmd = f"wkhtmltoimage --quality 80 '{url}' '{screenshot_path}'"
            
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        # Check if screenshot was created
        screenshot_file = Path(screenshot_path)
        if screenshot_file.exists() and screenshot_file.stat().st_size > 0:
            with open(screenshot_path, 'rb') as f:
                image_data = f.read()
            
            # Clean up
            os.unlink(screenshot_path)
            
            return Image(data=image_data, format='png')
        else:
            return f"Error: Screenshot failed. Command output: {process.stderr}"
    except Exception as e:
        return f"Error taking screenshot: {str(e)}"
    finally:
        # Clean up if file still exists
        if os.path.exists(screenshot_path):
            os.unlink(screenshot_path)

@mcp.tool()
async def ffuf_scan(ctx: Context, target: str, wordlist: str = None) -> str:
    """
    Run ffuf web content discovery scan
    
    Args:
        target: Target URL (e.g., http://example.com/)
        wordlist: Path to wordlist (default: uses dirb common wordlist)
    """
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    ctx.info(f"Running ffuf content discovery against {target}...")
    
    # Ensure the target URL ends with a slash + FUZZ placeholder
    if not target.endswith('/'):
        target += '/'
    if 'FUZZ' not in target:
        target += 'FUZZ'
    
    cmd = f"ffuf -u {target} -w {wordlist} -c -s"
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        output = result.stdout
        
        if output.strip():
            return f"# FFUF Content Discovery Results\n\n```\n{output}\n```"
        else:
            return "No results found with ffuf content discovery."
    except subprocess.TimeoutExpired:
        return "⚠️ FFUF scan timed out after 5 minutes"
    except Exception as e:
        return f"⚠️ Error running FFUF: {str(e)}"

# --- VULNERABILITY ASSESSMENT TOOLS ---
@mcp.tool()
async def vulnerability_scan(ctx: Context, target: str, scan_type: str = "web") -> str:
    """
    Run a vulnerability scan on the target
    
    Args:
        target: Target to scan (URL or IP address)
        scan_type: Type of scan (web, sql)
    """
    result = "# Vulnerability Scan Results\n\n"
    
    if scan_type.lower() == "web":
        # Run nikto web scan
        ctx.info(f"Running Nikto web vulnerability scan against {target}...")
        
        try:
            # Add http:// prefix if missing
            if not target.startswith(("http://", "https://")):
                target = f"http://{target}"
                
            cmd = f"nikto -h {target} -nointeractive -Display V"
            nikto_result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            result += f"## Nikto Web Vulnerability Scan\n\n```\n{nikto_result.stdout.strip()}\n```\n\n"
            
            # Extract vulnerability findings
            vulns = []
            for line in nikto_result.stdout.splitlines():
                if "+ " in line:
                    vulns.append(line.strip())
            
            if vulns:
                result += "### Key Findings\n\n"
                for vuln in vulns[:10]:  # Show top 10 findings
                    result += f"- {vuln}\n"
                if len(vulns) > 10:
                    result += f"- ...and {len(vulns) - 10} more findings\n"
                result += "\n"
        except subprocess.TimeoutExpired:
            result += "⚠️ Nikto scan timed out after 10 minutes\n\n"
        except Exception as e:
            result += f"⚠️ Nikto error: {str(e)}\n\n"
    
    elif scan_type.lower() == "sql":
        # Run sqlmap for SQL injection scanning
        ctx.info(f"Running SQLMap injection scan against {target}...")
        
        try:
            # Add http:// prefix if missing
            if not target.startswith(("http://", "https://")):
                target = f"http://{target}"
                
            # Use a safe test level with minimal requests
            cmd = f"sqlmap -u {target} --batch --level=1 --risk=1 --dbs --random-agent"
            sqlmap_result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            
            result += f"## SQLMap SQL Injection Scan\n\n```\n{sqlmap_result.stdout.strip()}\n```\n\n"
            
            # Check for successful identifications
            if "is vulnerable" in sqlmap_result.stdout:
                result += "### ⚠️ SQL Injection Vulnerabilities Found!\n\n"
                
                # Extract vulnerability types
                if "Parameter:" in sqlmap_result.stdout:
                    for line in sqlmap_result.stdout.splitlines():
                        if "Parameter:" in line:
                            result += f"- {line.strip()}\n"
                
                # Extract found databases if any
                if "available databases" in sqlmap_result.stdout:
                    result += "\n### Exposed Databases\n\n"
                    dbs_found = False
                    for line in sqlmap_result.stdout.splitlines():
                        if "[" in line and "]" in line and "available databases" not in line:
                            result += f"- {line.strip()}\n"
                            dbs_found = True
                    if not dbs_found:
                        result += "No database details extracted\n"
            else:
                result += "### No SQL Injection Vulnerabilities Detected\n\n"
                result += "The target appears to be secure against basic SQL injection attempts.\n"
        except subprocess.TimeoutExpired:
            result += "⚠️ SQLMap scan timed out after 10 minutes\n\n"
        except Exception as e:
            result += f"⚠️ SQLMap error: {str(e)}\n\n"
    
    return result

if __name__ == "__main__":
    mcp.run()