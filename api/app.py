from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import socket
import subprocess
import platform

app = FastAPI()

class ScanRequest(BaseModel):
    ip_range: str

@app.get("/")
def read_root():
    return {"message": "Welcome to the Network Scanner API"}

@app.post("/scan/")
def perform_scan(request: ScanRequest):
    ip_range = request.ip_range
    os_type = platform.system()
    if os_type == 'Windows':
        command = ["ping", "-n", "1"]
    else:
        command = ["ping", "-c", "1"]

    active_hosts = []
    for ip in range(int(ip_range.split('.')[0]), int(ip_range.split('.')[1]) + 1):
        ip_address = f"192.168.1.{ip}"
        try:
            result = subprocess.run(command + [ip_address], stdout=subprocess.PIPE)
            if result.returncode == 0:
                active_hosts.append(ip_address)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return {"active_hosts": active_hosts}
