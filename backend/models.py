from pydantic import BaseModel
from typing import Optional

class NmapOptions(BaseModel):
    target: str
    scan_type: Optional[str] = "-sV"
    os_detection: bool = False
    timing: Optional[str] = "-T3"
    port_range: Optional[str] = None
    output_format: Optional[str] = None
    extra_flags: Optional[str] = None

class GobusterOptions(BaseModel):
    target: str
    mode: str = "dir"
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    quiet: bool = False
    extra_flags: Optional[str] = None

class CurlOptions(BaseModel):
    target: str
    method: str = "GET"
    header: Optional[str] = None
    verbose: bool = False
    extra_flags: Optional[str] = None

class HydraOptions(BaseModel):
    target: str
    service: str = "ssh"
    user: str
    user_list: bool = False
    wordlist: str = "/usr/share/wordlists/passwords.txt"
    extra_flags: Optional[str] = None

class AircrackOptions(BaseModel):
    target_file: str
    wordlist: str = "/usr/share/wordlists/passwords.txt"
    bssid: Optional[str] = None
    extra_flags: Optional[str] = None

class Iperf3Options(BaseModel):
    target: str
    protocol: str = "tcp"
    time: int = 10
    bandwidth: Optional[str] = None

class MetasploitOptions(BaseModel):
    module: str
    rhosts: str
    rport: Optional[str] = None

class ExecuteRequest(BaseModel):
    tool: str
    current_step: str = "Step 1"
    options: dict

class ExecuteResponse(BaseModel):
    command: str
    stdout: str
    stderr: str
    exit_code: int
    ai_explanation: Optional[str] = None
