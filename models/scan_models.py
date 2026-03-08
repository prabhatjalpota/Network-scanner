from pydantic import BaseModel
from typing import List, Optional

# Model for individual scan request
class ScanRequest(BaseModel):
    target: str
    scan_type: str
    options: Optional[dict] = None

# Model for scan results
class ScanResult(BaseModel):
    target: str
    success: bool
    details: Optional[dict] = None
    errors: Optional[List[str]] = None

# Example usage
if __name__ == '__main__':
    scan_request = ScanRequest(target='192.168.1.1', scan_type='ping')
    print(scan_request.json())
    
    scan_result = ScanResult(target='192.168.1.1', success=True, details={'latency': '20ms'})
    print(scan_result.json())