# KaliMCP: AI-Powered Cybersecurity Research Partner

KaliMCP is a Model Context Protocol (MCP) server that turns Kali Linux tools into natural language-driven cybersecurity research capabilities accessible through AI clients.

## Features

- Run Kali Linux tools using natural language
- Auto-categorize tools by security function
- Get concise or detailed analysis of tool outputs
- Use predefined security workflows for common tasks
- Capture and analyze screenshots for visual security assessment

## Installation

1. Clone this repository:
```
git clone https://github.com/pir4cy/kali-mcp.git 
cd kali-mcp
```
2. Create a virtual environment and install dependencies:
```
python -m venv venv 
source venv/bin/activate 
pip install -r requirements.txt
```
3. Run the server:
```
python main.py
```

## Using with Claude Desktop

1. Install Claude Desktop from https://claude.ai/download
2. In Claude Desktop, go to Settings > MCP Servers > Add Server
3. Enter the MCP server details:
- Name: KaliMCP
- Command: python /path/to/kali-mcp/main.py

## Using with VS Code

1. Install the "GitHub Copilot" extension in VS Code
2. Configure the MCP server in settings.json:
```json
"github.copilot.chat.locales": {
  "kali-mcp": {
    "command": ["python", "/path/to/kali-mcp/main.py"]
  }
}
```
## Security Considerations
This tool is for legitimate security research and testing only
Only run against systems you own or have permission to test
The server implements safety checks to prevent dangerous commands
Some tools may require root privileges to run effectively.  

## License
MIT License

## Using KaliMCP

Once set up and connected to your AI client, you can use natural language to run tools:

1. **Run recon on a target**: "Run a basic reconnaissance scan on example.com"
2. **Analyze vulnerabilities**: "Check for web vulnerabilities on the target server"
3. **Get detailed output**: "Show me a detailed nmap scan of the local network"
4. **Research techniques**: "What tools should I use to analyze wireless network security?"

The server will translate these natural language requests into the appropriate Kali tool commands, execute them, and provide intelligent analysis of the results.