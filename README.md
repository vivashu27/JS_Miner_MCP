# 🔍 JS Miner MCP Server

A powerful Model Context Protocol (MCP) server that scans web pages and JavaScript files for exposed API keys, secrets, and sensitive credentials. Built with [FastMCP](https://github.com/jlowin/fastmcp), it integrates seamlessly with MCP clients like **Claude Desktop**, **Cursor**, and **LLM Studio**.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![MCP](https://img.shields.io/badge/Protocol-MCP-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## ✨ Features

- **🌐 URL Scanning** - Scan any web page for exposed secrets
- **📜 JavaScript Analysis** - Automatically discovers and scans linked `.js` files
- **📁 Local File Scanning** - Scan local files for hardcoded credentials
- **🎯 50+ Secret Patterns** - Detects a wide variety of tokens and keys:
  - AWS Access Keys
  - Google API Keys
  - GitHub Tokens (PAT, OAuth, Bot tokens)
  - Stripe Live Keys
  - Slack Tokens
  - JWT Tokens
  - Discord Tokens
  - SendGrid, Mailgun, Twilio API Keys
  - Bearer Tokens & OAuth Tokens
  - Private RSA/DSA Keys
  - And many more...
- **🔬 Entropy Analysis** - Uses Shannon entropy to reduce false positives
- **🤖 MCP Integration** - Works with any MCP-compatible AI client

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/vivashu27/JS_Miner_MCP.git
cd JS_Miner_MCP
```

2. **Install dependencies:**

```bash
pip install fastmcp httpx beautifulsoup4
```

3. **Run the server:**

```bash
python js_miner_mcp_server.py
```

---

## ⚙️ Configuration with MCP Clients

### Claude Desktop

Add the following to your Claude Desktop configuration file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "js-miner": {
      "command": "python",
      "args": ["path/to/js_miner_mcp_server.py"]
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "js-miner": {
      "command": "python",
      "args": ["path/to/js_miner_mcp_server.py"]
    }
  }
}
```

---

## 🛠️ Available Tools

### `scan_url`

Scans a web URL and its linked JavaScript files for secrets.

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | required | The website URL to scan |
| `scan_linked_js` | boolean | `true` | Whether to scan linked JS files |

**Example Usage (via AI client):**
```
Scan https://example.com for exposed API keys
```

### `scan_file`

Scans a local file for exposed secrets.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `file_path` | string | Absolute path to the file to scan |

**Example Usage (via AI client):**
```
Scan the file C:/projects/config.js for secrets
```

---

## 📊 Sample Output

```markdown
### Secret Scan Report for https://example.com

- **AWS Access Key** found in `https://example.com/app.js`
  - Entropy: 4.28
  - Snippet: `AKIA...3XYZ`

- **JWT Token** found in `https://example.com/auth.js`
  - Entropy: 5.12
  - Snippet: `eyJh...gBcd`
```

---

## 🔐 Detected Secret Types

| Category | Patterns |
|----------|----------|
| **Cloud Providers** | AWS Access Key, Google API Key |
| **Version Control** | GitHub Tokens (PAT, OAuth, Bot, Refresh) |
| **Payment Services** | Stripe Live Key, PayPal Client ID/Secret, Square Tokens |
| **Communication** | Slack Token, Discord Token, Twilio API Key |
| **Email Services** | SendGrid API Key, Mailgun API Key |
| **Authentication** | JWT, Bearer Token, OAuth Token, Session Token |
| **Hosting** | Heroku API Key |
| **Generic** | API Keys, Access Tokens, Private Keys |

---

## 🧪 How It Works

1. **URL Fetching** - Retrieves the HTML content of the target URL
2. **JS Discovery** - Parses `<script>` tags to find linked JavaScript files
3. **Pattern Matching** - Applies 50+ regex patterns to detect secrets
4. **Entropy Analysis** - Calculates Shannon entropy (threshold: 3.5) to filter false positives
5. **Report Generation** - Produces a structured markdown report

---

## ⚠️ Disclaimer

This tool is intended for **security research and authorized testing only**. Always ensure you have proper authorization before scanning any website or system. Unauthorized scanning may violate terms of service or applicable laws.

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Commit your changes (`git commit -am 'Add new secret pattern'`)
4. Push to the branch (`git push origin feature/new-pattern`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp)
- Inspired by security tools like TruffleHog and GitLeaks
- Thanks to the MCP protocol for enabling AI-tool integration

---

**Made with ❤️ for security researchers**
