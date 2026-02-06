from fastmcp import FastMCP
import httpx
import re
import math
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Initialize the MCP Server
mcp = FastMCP("Secret Scanner")

# --- Configuration ---

# Common regex patterns for sensitive data
# NOTE: These are patterns for detection. Validation requires API calls which we do not perform safely here.
PATTERNS = {
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey|secret|token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key (RSA/DSA)": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    # Authentication tokens
    "Bearer Token": r"(?i)(?:bearer|authorization)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-\.]{20,})[\"']?",
    "Authorization Header Token": r"(?i)authorization\s*:\s*(?:bearer\s+)?([a-zA-Z0-9_\-\.]{20,})",
    "Access Token": r"(?i)(?:access[_-]?token|access_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{20,})[\"']",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "OAuth Token": r"(?i)(?:oauth[_-]?token|oauth_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
    "Refresh Token": r"(?i)(?:refresh[_-]?token|refresh_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{20,})[\"']",
    "Session Token": r"(?i)(?:session[_-]?token|session_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
    # API Keys - expanded patterns
    "API Key in Variable": r"(?i)(?:const|let|var)\s+(?:api[_-]?key|apikey|api[_-]?token)\s*=\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
    "API Key in Object": r"(?i)(?:api[_-]?key|apikey|api[_-]?token)\s*:\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']",
    # Common service-specific tokens
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub Personal Access Token": r"gho_[a-zA-Z0-9]{36}",
    "GitHub OAuth Token": r"ghu_[a-zA-Z0-9]{36}",
    "GitHub Refresh Token": r"ghr_[a-zA-Z0-9]{36}",
    "Twitter Bearer Token": r"(?i)bearer\s+([A-Za-z0-9%]{50,})",
    "Facebook Access Token": r"(?i)(?:facebook|fb)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{50,})[\"']",
    "Discord Token": r"(?i)(?:discord[_-]?token|discord_token)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{50,})[\"']",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
    "Heroku API Key": r"(?i)heroku[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{36})[\"']",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun API Key": r"(?i)key-[a-zA-Z0-9]{32}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal Client ID": r"(?i)paypal[_-]?client[_-]?id[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{50,})[\"']",
    "PayPal Secret": r"(?i)paypal[_-]?secret[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{50,})[\"']",
    # Generic token patterns in common contexts
    "Token in Headers": r"(?i)(?:x-)?(?:api[_-]?key|token|auth[_-]?token|access[_-]?token)\s*:\s*([a-zA-Z0-9_\-\.]{20,})",
    "Token in Config": r"(?i)(?:config|env|process\.env)\.(?:api[_-]?key|token|auth[_-]?token|access[_-]?token)\s*=\s*[\"']([a-zA-Z0-9_\-\.]{20,})[\"']",
}

# Minimum Shannon entropy threshold to consider a string "random" enough to be a key
ENTROPY_THRESHOLD = 3.5 

# --- Helper Functions ---

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to determine if a string is random."""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_text(content: str, source_name: str) -> list:
    """Scans a string for secrets using defined patterns and entropy checks."""
    findings = []
    
    for name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            # Extract the actual secret group if present, else the whole match
            secret_candidate = match.group(1) if match.lastindex else match.group(0)
            
            # entropy check to reduce false positives
            entropy = calculate_entropy(secret_candidate)
            
            if entropy >= ENTROPY_THRESHOLD or "PRIVATE KEY" in name:
                findings.append({
                    "type": name,
                    "source": source_name,
                    "entropy": round(entropy, 2),
                    "snippet": secret_candidate[:4] + "..." + secret_candidate[-4:] if len(secret_candidate) > 10 else "***"
                })
            
    return findings

# --- MCP Tools ---

@mcp.tool()
def scan_url(url: str, scan_linked_js: bool = True) -> str:
    """
    Scans a web URL and optionally its linked JavaScript files for API keys and secrets.
    
    Args:
        url: The website URL to scan (e.g., https://example.com).
        scan_linked_js: If True, fetches and scans .js files referenced in <script> tags.
    """
    results = []
    visited_urls = set()
    
    try:
        # 1. Scan the main page
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            html_content = response.text
            
            results.extend(scan_text(html_content, url))
            
            # 2. Find and scan JS files if requested
            if scan_linked_js:
                soup = BeautifulSoup(html_content, 'html.parser')
                scripts = soup.find_all('script', src=True)
                
                for script in scripts:
                    js_url = urljoin(url, script['src'])
                    if js_url not in visited_urls:
                        visited_urls.add(js_url)
                        try:
                            js_res = client.get(js_url)
                            if js_res.status_code == 200:
                                results.extend(scan_text(js_res.text, js_url))
                        except Exception as e:
                            results.append({"error": f"Failed to scan JS {js_url}: {str(e)}"})

        if not results:
            return "No high-entropy secrets found using current patterns."
            
        # Format results for Claude
        report = f"### Secret Scan Report for {url}\n\n"
        for item in results:
            if "error" in item:
                report += f"- [ERROR] {item['error']}\n"
            else:
                report += f"- **{item['type']}** found in `{item['source']}`\n"
                report += f"  - Entropy: {item['entropy']}\n"
                report += f"  - Snippet: `{item['snippet']}`\n"
        
        return report

    except Exception as e:
        return f"Error scanning URL: {str(e)}"

@mcp.tool()
def scan_file(file_path: str) -> str:
    """
    Scans a local file for API keys and secrets.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        findings = scan_text(content, file_path)
        
        if not findings:
            return f"No secrets found in {file_path}."
            
        report = f"### Secret Scan Report for {file_path}\n\n"
        for item in findings:
             report += f"- **{item['type']}** (Entropy: {item['entropy']}): `{item['snippet']}`\n"
             
        return report
    except Exception as e:
        return f"Error reading file: {str(e)}"

if __name__ == "__main__":
    # Run the server using standard input/output (Stdio)
    mcp.run()