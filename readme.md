# Cybersecurity Scanning Pipeline

## Overview
This project is a **dynamic cybersecurity scanning pipeline** built with **Python, LangChain and LangGraph**, integrating multiple security tools to analyze a target domain based on user input. The execution flow is determined **dynamically by an LLM**, ensuring that only the required tools run as per the user's request.

## Features
- **Automatic Execution Flow:** The LLM determines the necessary tools based on the user's request.
- **Integrated Security Tools:**
  - **Nmap:** Port scanning.
  - **Gobuster:** Directory enumeration (depends on Nmap results).
  - **FFUF:** Fuzzing (depends on Gobuster results).
  - **SQLMap:** SQL injection testing.
- **Structured Data Extraction:** LLM extracts key information from tool outputs.
- **Automated SQL Injection Workflow:** SQLMap is run in an advanced mode to extract databases, tables, and data dynamically.

## Dependencies
Ensure you have the following installed:
- Python 3.8+
- `langchain`
- `langgraph`
- `langchain_groq`
- `python-dotenv`
- `subprocess` (built-in)
- Security tools:
  - `nmap`
  - `gobuster`
  - `ffuf`
  - `sqlmap`

### Installation
```bash
# Clone the repository
git clone https://github.com/Rahil71/Cybersecurity-Scanning-Pipeline.git
cd cybersecurity-pipeline

# Install dependencies
pip install -r requirements.txt

# Ensure security tools are installed
sudo apt install nmap gobuster ffuf sqlmap
```

## Configuration
### Setting Up API Keys
Create a `.env` file in the root directory and add your **Groq API key**:
```
GROQ_API_KEY=your_api_key_here
```

## Execution Flow
1. **User Request Interpretation:**
   - Extracts target domain and required scans using the LLM.
2. **Nmap Scan (if selected):**
   - Runs a TCP SYN scan to detect open ports.
3. **Gobuster Scan (if selected):**
   - Runs only if **Nmap** found open HTTP/HTTPS ports.
4. **FFUF Scan (if selected):**
   - Runs only if **Gobuster** found valid directories.
5. **SQLMap Execution (if selected):**
   - Runs independently if a target URL is provided.
   - If executed, it extracts databases and tables dynamically.

## Usage
Run the script and provide a request in natural language:
```bash
python main.py
```
Example inputs:
```bash
Enter your scan request: Scan youtube for SQL vulnerabilities.
```
```bash
Enter your scan request: Perform full recon on testphp.vulnweb.com including all scans.
```

## Detailed Breakdown of Components

### `interpret_user_request(user_input: str) -> List[str]`
- Uses **LLM** to extract:
  - Target domain.
  - Required security scans.
  - Adjusted execution flow based on dependencies.

### `nmap_scan(target: str) -> List[int]`
- Runs Nmap with **aggressive scanning parameters** to find open ports.
- Extracts open ports using **regex pattern matching**.

### `run_gobuster(target: str, open_ports: List[int]) -> List[str]`
- Runs only if HTTP(S) ports **80, 443, 8000, 8080, 8443** are open.
- Uses a wordlist to enumerate directories.
- Extracts found directories using regex.

### `ffuf_scan(target: str, open_ports: List[int], directories: List[str]) -> List[str]`
- Runs only if Gobuster finds directories.
- Uses **fuzzing techniques** to discover additional endpoints.
- Extracts valid responses based on HTTP status codes **200, 301, 302**.

### `run_sqlmap(target_url: str) -> str`
- Runs SQLMap in **batch mode**.
- Extracts tested URLs and injection results.
- Sends output to **LLM for structured analysis**.

### `execute_advanced_sqlmap(target_url, llm_analysis)`
- Extracts valid SQL injectable URLs.
- Fetches **databases** dynamically.
- Fetches **tables** for each database.
- Dumps table contents if found.

## Example Outputs
### **Nmap Scan Output:**
```
Running Nmap on testphp.vulnweb.com...
Open Ports Found: [80, 443, 3306]
```
### **Gobuster Scan Output:**
```
Running Gobuster on testphp.vulnweb.com...
Directories Found: ['/admin', '/uploads']
```
### **SQLMap Execution Output:**
```
Running SQLMap on http://testphp.vulnweb.com...
Fetching database names...
Databases Found: ['acuart', 'information_schema']
```

## Security Considerations
- This tool should **only** be used for ethical penetration testing with proper authorization.
- Scanning without permission may **violate legal policies**.
- Consider running scans in a **sandboxed environment**.

## Acknowledgments
- **Nmap** for network scanning.
- **Gobuster** and **FFUF** for directory and fuzz testing.
- **SQLMap** for automated SQL injection testing.
- **LangChain & Groq** for AI-driven decision-making.

---
**Disclaimer:** Use this tool **only on authorized targets**. Unauthorized use is illegal.

