This project is an AI-powered threat intelligence tool that acts as a virtual Security Operations Center (SOC) analyst. It uses LangChain agents to automatically analyze indicators of compromise (IOCs) and provide data-driven threat assessments.
Instead of manually checking each IP address or domain in VirusTotal's web interface, security analysts can simply ask natural language questions and receive comprehensive threat intelligence reports.
✨ Features
Currently Implemented:

✅ IP Address Analysis - Check IP reputation against VirusTotal's database
✅ Domain Analysis - Verify domain safety and reputation
✅ Natural Language Interface - Ask questions in plain English
✅ AI-Powered Agent - Intelligent decision-making using Google's Gemini
✅ Multi-Source Context - Agent understands context across multiple queries

Roadmap (Coming Soon):

🔄 URL Scanning
🔄 File Hash Verification
🔄 Malware Footprint Analysis
🔄 Batch Processing
🔄 Report Generation

🎯 Problem It Solves
Security analysts waste hours manually:

Copying IOCs from alerts
Pasting them into VirusTotal
Interpreting results
Writing up findings

This tool automates that workflow. Ask a question, get instant threat intelligence.
🚀 Demo
bashCurrent User: Is 8.8.8.8 malicious?

> Entering new AgentExecutor chain...
Tool: Currently checking ip address: VirusTotal Results: 0 malicious, 0 suspicious, 89 harmless

AGENT RESPONDING
The IP address 8.8.8.8 has been analyzed. VirusTotal reports 0 malicious, 
0 suspicious, and 89 harmless detections. Therefore, 8.8.8.8 is not considered malicious.
bashCurrent User: Check if google.com is safe

> Entering new AgentExecutor chain...
Tool: Currently checking domains: VirusTotal Results: 0 malicious, 0 suspicious, 94 harmless

AGENT RESPONDING
The domain google.com has been analyzed. VirusTotal reports 0 malicious,
0 suspicious, and 94 harmless detections. This domain is safe.
🛠️ Tech Stack

AI Framework: LangChain (agent orchestration)
LLM: Google Gemini 2.5 Flash
Threat Intelligence: VirusTotal API
Language: Python 3.13+
Libraries: langchain, requests, python-dotenv, langchain-google-genai

📦 Installation
Prerequisites

Python 3.13 or higher
VirusTotal API key (Get one here)
Google Gemini API key (Get one here)

Setup

Clone the repository

bashgit clone https://github.com/yourusername/threat-intel-agent.git
cd threat-intel-agent

Create virtual environment

bashpython -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

Install dependencies

bashpip install -r requirements.txt

Configure environment variables

Create a .env file in the project root:
envGEMINI_API_KEY=your_gemini_api_key_here
VIRUS_API_KEY=your_virustotal_api_key_here

Run the tool

bashpython main.py
💻 Usage
Basic Usage
bashpython main.py
```

Then enter your query:
```
Current User: Is 1.1.1.1 malicious?
Current User: Check facebook.com
Current User: Analyze the domain example.com
```

### Example Queries

- `Is 192.168.1.1 malicious?`
- `Check if google.com is safe`
- `Analyze this IP: 8.8.8.8`
- `What's the reputation of cloudflare.com?`

## 🏗️ Architecture
```
User Query
    ↓
LangChain Agent (Gemini 2.5)
    ↓
Tool Selection (IP or Domain checker)
    ↓
VirusTotal API Call
    ↓
Result Processing
    ↓
Natural Language Response
```

### Agent Tools

The AI agent has access to these tools:

1. **checking_ip** - Analyzes IP addresses via VirusTotal
2. **checking_domains** - Analyzes domains via VirusTotal
3. **checking_url** - (Coming soon) URL analysis
4. **checking_filehash** - (Coming soon) File hash verification
5. **checking_virus_footprint** - (Coming soon) Malware footprint analysis

The agent intelligently decides which tool to use based on the user's query.

## 📁 Project Structure
```
threat-intel-agent/
├── main.py              # Main agent orchestration
├── tools.py             # IP checking function
├── test_domains.py      # Domain checking function
├── .env                 # API keys (not committed)
├── requirements.txt     # Python dependencies
└── README.md           # This file
🔐 Security Considerations

API Keys: Never commit .env file to version control
Rate Limits: VirusTotal free tier has request limits (4 requests/minute)
Data Privacy: All queries are sent to VirusTotal and Google's Gemini API
Use Case: Intended for security research and analysis only

🚧 Known Limitations

Currently only supports IP and domain analysis
Command-line interface only (no GUI)
No batch processing yet
No historical data storage
Rate-limited by VirusTotal free tier

🎓 What I Learned
Building this project taught me:

How to build LangChain agents from scratch
Tool calling and function orchestration
API integration patterns
Natural language interfaces for technical tools
Security threat intelligence workflows

🔮 Future Enhancements
Phase 1 (Next 2 weeks):

 Complete URL and file hash checking
 Add batch processing (CSV upload)
 Implement result caching

Phase 2 (Next month):

 Build web interface (Streamlit)
 Add multiple threat intel sources (AbuseIPDB, URLhaus)
 PostgreSQL database for historical data
 Automated report generation

Phase 3 (Long-term):

 RESTful API
 Integration with SIEM tools
 Real-time alerting
 Custom threat scoring

🤝 Contributing
This is a learning project, but suggestions are welcome!
📄 License
MIT License - feel free to use this for learning purposes.
👤 Author
Your Name

GitHub: Bruceisacat
LinkedIn: https://www.linkedin.com/in/justin-paulino-36817b2b2/
Email: justinpaulino721@yahoo.com


🙏 Acknowledgments

VirusTotal for threat intelligence API
LangChain for agent framework
Google for Gemini API access
