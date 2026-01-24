# Email Phishing Scanner

A **secure**, **production-ready** email phishing scanner built with FastAPI. Analyzes `.eml` files for phishing indicators using static analysis only—**no code execution, no external requests, no rendering**.

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🛡️ Security Features

### Core Security Principles

1. **No Execution**: Never executes, opens, or renders email content
2. **No Network Requests**: No URL fetching, no external API calls
3. **Memory-Only Processing**: No persistent file storage
4. **Static Analysis Only**: Uses Python's standard `email` library for safe parsing
5. **File Type Validation**: Only accepts `.eml` files with content validation

### What Makes This Safe?

- ✅ Parses emails using RFC 822/MIME standard library
- ✅ Extracts text/plain content only (no HTML rendering)
- ✅ Analyzes attachment metadata without opening files
- ✅ Calculates SHA-256 hashes without executing content
- ✅ Uses regex for URL extraction (no following redirects)
- ✅ All processing happens in isolated memory
- ✅ Data is discarded immediately after analysis

---

## 🎯 Features

### 1. Header Analysis
- Extracts key headers: From, To, Subject, Date, Message-ID, Reply-To, Return-Path
- Analyzes full Received header chain
- Parses Authentication-Results (SPF, DKIM, DMARC)
- Detects domain mismatches (From vs Reply-To, From vs Return-Path)

### 2. Body Analysis
- Extracts text/plain content only
- Safely extracts URLs using regex
- Flags suspicious URL patterns:
  - IP-based URLs
  - URL shorteners
  - Punycode domains (xn--)
  - Suspicious TLDs
  - Excessive subdomains

### 3. Attachment Analysis (Safe)
- Lists attachments without opening them
- Extracts: filename, MIME type, size, SHA-256 hash
- Flags risky file types:
  - Executables (.exe, .js, .vbs, etc.)
  - Macro-enabled documents (.docm, .xlsm)
  - Double extensions
  - Archive files

### 4. Risk Scoring Engine
- Rule-based, explainable scoring (0-100)
- Three verdicts: LOW (0-30), MEDIUM (31-60), HIGH (61-100)
- Detailed breakdown of each score component
- Clear explanations for all findings

### 5. REST API
- `POST /api/scan` - Upload and scan .eml file
- `GET /api/health` - Health check endpoint
- Comprehensive JSON response with all findings

### 6. Web UI
- Simple, user-friendly single-page interface
- Drag-and-drop file upload
- Visual risk indicators
- Detailed results display
- No frameworks required (vanilla HTML/CSS/JS)

---

## 📁 Project Structure

```
email_scanner/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── routes/
│   │   ├── __init__.py
│   │   └── scan.py            # Scan endpoint
│   └── services/
│       ├── __init__.py
│       ├── parser.py          # Safe email parser
│       ├── headers.py         # Header analysis
│       ├── urls.py            # URL analysis
│       ├── attachments.py     # Attachment analysis
│       └── scoring.py         # Risk scoring engine
├── templates/
│   └── index.html             # Web UI
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- pip

### Setup

1. **Clone or download this project**
   ```bash
   cd email_scanner
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🎮 Usage

### Running the Application

```bash
python -m app.main
```

Or with uvicorn directly:
```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The application will start on `http://127.0.0.1:8000`

### Using the Web Interface

1. Open your browser and navigate to `http://127.0.0.1:8000`
2. Drag and drop an `.eml` file or click to browse
3. Click "Scan Email"
4. Review the detailed analysis results

### Using the API

#### Scan an Email
```bash
curl -X POST "http://127.0.0.1:8000/api/scan" \
  -F "file=@sample.eml"
```

#### API Response Example
```json
{
  "filename": "phishing_example.eml",
  "verdict": "HIGH",
  "score": 75,
  "risk_summary": "This email shows strong indicators of phishing...",
  "scoring_reasons": [
    {
      "category": "Authentication",
      "issue": "SPF check failed",
      "points": 20,
      "explanation": "Sender is not authorized to send from this domain"
    }
  ],
  "headers": {
    "from": "sender@example.com",
    "subject": "Urgent: Verify Your Account"
  },
  "urls": {
    "count": 2,
    "urls": [...]
  },
  "attachments": {
    "count": 1,
    "attachments": [...]
  },
  "all_issues": [...]
}
```

---

## 🧪 Testing

### Get Sample .eml Files

You can create test `.eml` files by:
1. Saving emails from your email client as `.eml` format
2. Using online tools to generate test emails
3. Creating them manually with proper RFC 822 format

### Example Test .eml File

Create a file named `test.eml`:
```
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Thu, 23 Jan 2026 10:00:00 +0000
Message-ID: <12345@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

This is a test email with a link: http://192.168.1.1/phishing
```

---

## 🔒 Security Considerations

### What This Tool Does NOT Do

❌ **Does not execute** any code from emails  
❌ **Does not fetch** URLs or follow redirects  
❌ **Does not open** attachments  
❌ **Does not render** HTML content  
❌ **Does not make** external network requests  
❌ **Does not store** files persistently  

### Limitations

- **Static Analysis Only**: Cannot detect all phishing attempts
- **No Sandboxing**: Does not execute suspicious files in a sandbox
- **No Threat Intelligence**: Does not check URLs/hashes against threat databases
- **No Machine Learning**: Uses rule-based detection only

### Recommended Use

This tool is designed for:
- ✅ Initial triage of suspicious emails
- ✅ Educational purposes
- ✅ Security awareness training
- ✅ Quick analysis without external dependencies

**Always combine with:**
- User security awareness training
- Email gateway filters
- Multi-factor authentication
- Regular security audits

---

## 📊 Risk Scoring

### Score Ranges
- **0-30**: LOW risk - Minimal indicators
- **31-60**: MEDIUM risk - Some concerning patterns
- **61-100**: HIGH risk - Strong phishing indicators

### Scoring Components

| Issue Type | Points | Severity |
|------------|--------|----------|
| SPF Failure | 20 | HIGH |
| DKIM Failure | 20 | HIGH |
| DMARC Failure | 15 | HIGH |
| IP-based URL | 25 | HIGH |
| Punycode Domain | 20 | HIGH |
| Double Extension | 30 | HIGH |
| Executable Attachment | 25 | HIGH |
| Domain Mismatch (From/Reply-To) | 15 | MEDIUM |
| URL Shortener | 10 | MEDIUM |
| Macro Document | 15 | MEDIUM |

---

## 🛠️ Development

### Code Structure

Each service is **modular** and **independently testable**:

- **parser.py**: Safe email parsing using Python's `email` library
- **headers.py**: Header analysis and domain validation
- **urls.py**: URL extraction and risk assessment
- **attachments.py**: Attachment metadata analysis
- **scoring.py**: Rule-based risk scoring with explanations

### Adding New Rules

To add new detection rules:

1. Add analysis logic to the appropriate service
2. Update the scoring engine in `scoring.py`
3. Add corresponding UI display in `index.html`

### Configuration

Key settings in `app/main.py`:
```python
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
HOST = "127.0.0.1"
PORT = 8000
```

---

## 📝 API Documentation

Once running, visit:
- Swagger UI: `http://127.0.0.1:8000/api/docs`
- ReDoc: `http://127.0.0.1:8000/api/redoc`

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. Security principles are maintained
2. No execution of email content
3. No external network requests
4. Code is well-documented
5. Tests are included

---

## 📄 License

This project is provided as-is for educational and security research purposes.

---

## ⚠️ Disclaimer

This tool is for **educational and analysis purposes only**. It provides indicators but is not a complete security solution. Always:

- Verify suspicious emails through official channels
- Never trust email content blindly
- Use defense-in-depth security strategies
- Keep systems and software updated
- Train users on phishing awareness

**The authors are not responsible for any damage or loss caused by use or misuse of this tool.**

---

## 📧 Support

For issues or questions, please review the code comments and documentation. The code is extensively commented to explain security decisions.

---

## 🎓 Educational Value

This project demonstrates:
- Secure email parsing techniques
- Static malware analysis principles
- Rule-based threat detection
- Explainable AI/scoring systems
- FastAPI best practices
- Security-first development

---

**Built with security in mind. Analyze safely.** 🛡️
