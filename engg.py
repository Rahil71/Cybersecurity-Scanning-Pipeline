import subprocess
import re
import os
from typing import TypedDict, List
from langchain_groq import ChatGroq
from langchain.schema import SystemMessage, HumanMessage
from dotenv import load_dotenv
import ast
from langgraph.graph import StateGraph, END

load_dotenv()

llm = ChatGroq(model_name="llama-3.3-70b-versatile", groq_api_key=os.getenv("GROQ_API_KEY"))

class ScanState(TypedDict):
    target: str
    open_ports: List[int]
    directories: List[str]
    sqlmap_results: str
    requested_scans: List[str]

def interpret_user_request(user_input: str) -> tuple:
    prompt = f"""
    You are a cybersecurity expert. A user requested a security scan.

    User request: "{user_input}"

    Extract the following:
    - The target domain (convert names like 'YouTube' to 'www.youtube.com')
    - The scans requested (Nmap, Gobuster, FFUF, SQLMap)
    - It should follow this hierarchy(most of the times):
    for nmap: none  
    for gobuster: nmap
    for ffuf: nmap, gobuster
    for sqlmap: none
    as per any requested scan by the user

    you have the rights to change the execution flow by only selecting needed tools for user's request
    Output format:
    Target: <domain>
    Scans: <comma-separated list of scans>
    """

    response = llm.invoke([SystemMessage(content="You are a cybersecurity expert."), HumanMessage(content=prompt)])

    target_match = re.search(r"Target:\s*(\S+)", response.content)
    scans_match = re.search(r"Scans:\s*([\w,\s]+)", response.content)

    target = target_match.group(1) if target_match else "unknown"
    scans = scans_match.group(1).split(", ") if scans_match else []

    return target, scans

def nmap_scan(target: str) -> List[int]:
    print(f"Running Nmap on {target}...")

    command = f"sudo nmap -p- -sS -T4 --min-rate 1000 --open -vv {target}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    open_ports = [int(match.group(1)) for line in result.stdout.split("\n") if (match := re.match(r"(\d+)/tcp\s+open", line))]

    print(f"🔹 Open Ports Found: {open_ports}\n")
    return open_ports

def run_gobuster(target: str, open_ports: List[int]) -> List[str]:
    print(f"Running Gobuster on {target}...")

    ports = [80, 443, 8000, 8080, 8443]
    target_url = next((f"{'https' if p in [443, 8443] else 'http'}://{target}" for p in open_ports if p in ports), None)

    if not target_url:
        print("No HTTP/HTTPS port found\n")
        return []

    wordlist_path = os.path.expanduser("~/wordlists/common.txt")
    command = f"gobuster dir -u {target_url} -w {wordlist_path} -q"

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, text=True)
    directories = [match.group(1) for line in process.stdout if (match := re.search(r"(/[\w\-.~%]+)\s+\(Status: \d+\)", line))]

    process.wait()
    print(f"Directories Found: {directories}\n")
    return directories

def ffuf_scan(target: str, open_ports: List[int], directories: List[str]) -> List[str]:
    print(f"Running FFUF on {target}...")

    if not directories:
        print("⚠️ No directories found, skipping FFUF\n")
        return []

    scheme = "https" if 443 in open_ports or 8443 in open_ports else "http"
    target_url = f"{scheme}://{target}"
    
    print(f"Target URL: {target_url}")

    wordlist_path = os.path.expanduser("~/wordlists/common.txt")
    ffuf_results = []

    for directory in directories:
        fuzz_url = f"{target_url}{directory}/FUZZ"
        print(f"Fuzz URL: {fuzz_url}")

        command = f"ffuf -u {fuzz_url} -w {wordlist_path} -mc 200,301,302 -t 50 -s"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, text=True)
        
        ffuf_results.extend(match.group(1) for line in process.stdout if (match := re.search(r"(\S+)", line)))
        process.wait()

    print(f"FFUF Results: {ffuf_results}\n")
    return ffuf_results

def run_sqlmap(target_url):
    print(f"Running SQLMap on {target_url}...")

    command = f"sqlmap -u \"{target_url}\" --crawl 2 --batch"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()

    full_output = stdout + "\n" + stderr
    print(f"SQLMap Output:\n{full_output}")

    return analyze_sqlmap_output(full_output)

def analyze_sqlmap_output(sqlmap_output):
    print("Sending SQLMap output to LLM for analysis...")

    prompt = f"""
    You are a cybersecurity expert. A user executed SQLMap.

    SQLMap Output:
    {sqlmap_output}

    Extract:
    - URLs tested
    - Available databases
    - Table names (if found)
    - Remove "(skipped)" written in urls for example: `http://testphp.vulnweb.com/comment.php?aid=1` (skipped)
    - User data (if available)

    Output format:
    URL(s):
    All the urls in this format (do no add backticks or double inverted comma or anything only simple URL):
    http://testphp.vulnweb.com/comment.php?aid=1
    """

    response = llm.invoke([SystemMessage(content="You are a cybersecurity expert."), HumanMessage(content=prompt)])
    print(f"LLM Analysis:\n{response.content}")

    return response.content

def find_databases_with_llm(sqlmap_output) -> List[str]:
    print("Checking for databases in SQLMap output...")

    prompt = f"""
    You are a cybersecurity expert. Analyze the SQLMap output.

    SQLMap Output:
    {sqlmap_output}

    Extract:
    - If no databases are found, return an empty list: []
    - If databases exist, return ONLY a valid Python list: ['Yes', 'db1', 'db2', ...] 
    - DO NOT include any extra text, explanations, or formatting.

    Example SQLMap output:
    [12:34:18] [INFO] fetching database names
    available databases [2]:
    [*] acuart
    [*] information_schema

    Expected Output:
    ['Yes', 'acuart', 'information_schema']
    """

    response = llm.invoke([SystemMessage(content="You are a cybersecurity expert."), HumanMessage(content=prompt)])
    response_text = response.content.strip()

    try:
        extracted_data = ast.literal_eval(response_text)
        if not isinstance(extracted_data, list):
            raise ValueError("Invalid format received from LLM.")
    except (SyntaxError, ValueError):
        print(f"LLM returned unexpected output: {response_text}")
        return []

    if not extracted_data:
        print(f"No databases found.")
        return []

    databases = extracted_data[1:]
    print(f"Databases Found: {databases}")
    return databases

def find_tables_with_llm(sqlmap_output) -> List[str]:
    print("Checking for tables in SQLMap output...")

    prompt = f"""
    You are a cybersecurity expert. Analyze the SQLMap output.

    SQLMap Output:
    {sqlmap_output}

    Extract:
    - If no tables are found, return an empty list: []
    - If tables exist, return only table names as a valid Python list: ['table1', 'table2', ...]

    Strictly return ONLY a valid Python list and nothing else.
    """

    response = llm.invoke([SystemMessage(content="You are a cybersecurity expert."), HumanMessage(content=prompt)])
    response_text = response.content.strip()
    
    print(f"LLM Response for Tables:\n{response_text}")

    try:
        extracted_data = ast.literal_eval(response_text)
        if not isinstance(extracted_data, list):
            raise ValueError("Invalid format received from LLM.")
    except (SyntaxError, ValueError):
        print(f"LLM returned unexpected output: {response_text}")
        return []

    if not extracted_data:
        print(f"No tables found.")
        return []

    print(f"Tables Found: {extracted_data}")
    return extracted_data


def execute_advanced_sqlmap(target_url, llm_analysis):
    print("Running advanced SQLMap scans...")

    urls = re.findall(r"(http[s]?://[^\s]+)", llm_analysis)
    
    for url in urls:
        print(f"Fetching databases for {url}...")
        command = f"sqlmap -u \"{url}\" --dbs --batch"
        
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        sqlmap_output = stdout + "\n" + stderr

        databases = find_databases_with_llm(sqlmap_output)
        if not databases:
            print(f"No databases found for {url}, moving to the next URL...\n")
            continue

        for db in databases:
            print(f"Fetching tables in database: {db}...")
            table_command = f"sqlmap -u \"{url}\" -D {db} --tables --batch"

            process = subprocess.Popen(table_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            table_output = stdout + "\n" + stderr

            tables = find_tables_with_llm(table_output)
            if not tables:
                print(f"No tables found in database {db}.")
                continue

            for table in tables:
                print(f"Dumping data from table: {table} in database: {db}...")
                dump_command = f"sqlmap -u \"{url}\" -D {db} -T {table} --dump --batch"
                subprocess.run(dump_command, shell=True)

def should_run_nmap(state: ScanState) -> str:
    return "run_nmap" if "Nmap" in state.get("requested_scans", []) else "end"

def should_run_gobuster(state: ScanState) -> str:
    if "Gobuster" in state.get("requested_scans", []) and state.get("open_ports"):
        return "run_gobuster"
    return "end"

def should_run_ffuf(state: ScanState) -> str:
    if "FFUF" in state.get("requested_scans", []) and state.get("directories"):
        return "run_ffuf"
    return "end"

def should_run_sqlmap(state: ScanState) -> str:
    return "run_sqlmap" if "SQLMap" in state.get("requested_scans", []) else "end"

def workflow_setup(state: ScanState) -> ScanState:
    print(f"\n **Target:** {state['target']}")
    print(f"**Scans Requested:** {', '.join(state['requested_scans'])}\n")
    return state

def nmap_node(state: ScanState) -> ScanState:
    state["open_ports"] = nmap_scan(state["target"])
    return state

def gobuster_node(state: ScanState) -> ScanState:
    state["directories"] = run_gobuster(state["target"], state["open_ports"])
    return state

def ffuf_node(state: ScanState) -> ScanState:
    new_dirs = ffuf_scan(state["target"], state["open_ports"], state["directories"])
    state["directories"].extend(new_dirs)
    return state

def sqlmap_node(state: ScanState) -> ScanState:
    sqlmap_output = run_sqlmap(state["target"])
    execute_advanced_sqlmap(state["target"], sqlmap_output)
    state["sqlmap_results"] = sqlmap_output
    return state

def sqlmap_check_node(state: ScanState) -> ScanState:
    return state

def ffuf_check_node(state: ScanState) -> ScanState:
    return state

def build_workflow():
    builder = StateGraph(ScanState)

    # Add all nodes
    builder.add_node("setup", workflow_setup)
    builder.add_node("nmap", nmap_node)
    builder.add_node("gobuster", gobuster_node)
    builder.add_node("ffuf", ffuf_node)
    builder.add_node("sqlmap", sqlmap_node)
    builder.add_node("sqlmap_check", sqlmap_check_node)
    builder.add_node("ffuf_check", ffuf_check_node)

    # Set entry point
    builder.set_entry_point("setup")

    # Add conditional edges
    builder.add_conditional_edges(
        "setup",
        should_run_nmap,
        {"run_nmap": "nmap", "end": "sqlmap_check"}
    )

    builder.add_conditional_edges(
        "nmap",
        should_run_gobuster,
        {"run_gobuster": "gobuster", "end": "ffuf_check"}
    )

    builder.add_conditional_edges(
        "gobuster",
        should_run_ffuf,
        {"run_ffuf": "ffuf", "end": "sqlmap_check"}
    )

    builder.add_conditional_edges(
        "ffuf_check",
        should_run_ffuf,
        {"run_ffuf": "ffuf", "end": "sqlmap_check"}
    )

    builder.add_conditional_edges(
        "sqlmap_check",
        should_run_sqlmap,
        {"run_sqlmap": "sqlmap", "end": END}
    )

    builder.add_conditional_edges(
        "ffuf",
        should_run_sqlmap,
        {"run_sqlmap": "sqlmap", "end": END}
    )

    return builder.compile()

if __name__ == "__main__":
    user_request = input("Enter your scan request: ")
    target, requested_scans = interpret_user_request(user_request)

    initial_state = ScanState(
        target=target,
        open_ports=[],
        directories=[],
        sqlmap_results="",
        requested_scans=requested_scans
    )

    workflow = build_workflow()
    workflow.invoke(initial_state)