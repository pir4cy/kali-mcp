# utils/command_builder.py
import re
import shlex
import logging

logger = logging.getLogger('kali-mcp.command_builder')

# List of dangerous commands that should not be run
DANGEROUS_PATTERNS = [
    r'\brm\s+(-[rf]+\s+)?(\/|\~|\.\.)',  # Dangerous rm commands
    r'\b(chmod|chown)\s+[0-7]{3}\s+\/',  # Recursive permission changes on /
    r'>(>)?(\s+)?\/etc\/',                # Writing to /etc
    r'>(>)?(\s+)?\/bin\/',                # Writing to /bin
    r'\bdrop\s+tables?\b',                # SQL dropping tables
    r'\bdelete\s+from\b',                 # SQL deleting data
    r'\btruncate\s+table\b',              # SQL truncating
    r'\breboot\b',                        # System reboot
    r'\bshutdown\b',                      # System shutdown
    r'\bsystemctl\s+(stop|restart)\b',    # Stopping services
    r'\bformat\b',                        # Formatting drives
    r'\bmkfs\b',                          # Making filesystems
    r';.*rm',                             # Command chaining with rm
    r'&&.*rm',                            # Command chaining with rm
    r'\|\|.*rm',                          # Command chaining with rm
    r'\beval\b',                          # Eval
    r'\bexec\b',                          # Exec
    r'\bsource\b',                        # Source
    r'\bbase64\s+.*\|',                   # Base64 piping
]

TOOL_SANITIZATION_RULES = {
    'nmap': {
        'allowed_args': ['-sS', '-sT', '-sV', '-A', '-T', '-p', '-O', '--script'],
        'forbidden_args': ['--script=exploit', '--script=brute']
    },
    'sqlmap': {
        'allowed_args': ['--url', '--forms', '--dbms', '--technique'],
        'forbidden_args': ['--os-shell', '--os-cmd', '--os-pwn']
    },
    'metasploit': {
        'allowed_args': ['-h', '--help', '-L', '--list'],
        'forbidden_args': []  # Restrict actual exploitation
    },
    # More tool rules would go here
}

def build_command(tool: str, arguments: str) -> str:
    """
    Build and validate a command to run a tool with arguments
    
    Args:
        tool: The tool to run
        arguments: The arguments to pass to the tool
        
    Returns:
        A properly sanitized command string or None if invalid
    """
    # Basic sanity check
    if not tool or not isinstance(tool, str) or not isinstance(arguments, str):
        logger.error("Invalid tool or arguments type")
        return None
    
    # Remove any potentially dangerous shell constructs
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, arguments, re.IGNORECASE):
            logger.warning(f"Dangerous pattern detected in command arguments: {arguments}")
            return None
    
    # Check for command chaining or injection attempts
    suspicious_chars = [';', '&&', '||', '`', '$', '>', '<', '|', '\\']
    for char in suspicious_chars:
        if char in tool:
            logger.warning(f"Suspicious character '{char}' in tool name")
            return None
    
    # Apply tool-specific sanitization
    if tool in TOOL_SANITIZATION_RULES:
        rules = TOOL_SANITIZATION_RULES[tool]
        
        # Check for forbidden arguments
        for forbidden in rules['forbidden_args']:
            if forbidden in arguments:
                logger.warning(f"Forbidden argument '{forbidden}' for tool {tool}")
                return None
    
    # Build the final command
    try:
        # Validate argument format
        parsed_args = shlex.split(arguments)
        final_command = f"{tool} {arguments}"
        logger.info(f"Built command: {final_command}")
        return final_command
    except Exception as e:
        logger.error(f"Error parsing command arguments: {str(e)}")
        return None