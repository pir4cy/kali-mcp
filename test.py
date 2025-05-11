import shutil
import os

print("PATH:", os.environ.get("PATH"))
print("nmap:", shutil.which("nmap"))
print("nikto:", shutil.which("nikto"))
print("whois:", shutil.which("whois"))
print("python:", shutil.which("python"))
