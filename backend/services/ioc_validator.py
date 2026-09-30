import re
import ipaddress
from urllib.parse import urlparse

def validate_indicator(value: str):
    if not value or not isinstance(value, str):
        return {"valid": False, "indicator_type": "UNKNOWN", "normalized_value": "", "validation_notes": "Input is empty or invalid format"}
    
    val = value.strip()
    
    # 1. IP Validation (IPv4 / IPv6)
    try:
        ip_obj = ipaddress.ip_address(val)
        return {
            "valid": True,
            "indicator_type": "IP",
            "normalized_value": str(ip_obj),
            "validation_notes": f"Valid standard {'IPv4' if ip_obj.version == 4 else 'IPv6'} syntax"
        }
    except ValueError:
        pass

    # 2. CVE ID Validation (CVE-YYYY-NNNN+)
    if re.match(r"^CVE-\d{4}-\d{4,7}$", val, re.IGNORECASE):
        return {
            "valid": True,
            "indicator_type": "CVE_ID",
            "normalized_value": val.upper(),
            "validation_notes": "Conforms to standard CVE specification"
        }

    # 3. Hash Validation (MD5, SHA-1, SHA-256)
    if re.match(r"^[a-fA-F0-9]{32}$", val):
        return {"valid": True, "indicator_type": "FILE_HASH", "normalized_value": val.lower(), "validation_notes": "Syntactically valid MD5 hash"}
    if re.match(r"^[a-fA-F0-9]{40}$", val):
        return {"valid": True, "indicator_type": "FILE_HASH", "normalized_value": val.lower(), "validation_notes": "Syntactically valid SHA-1 hash"}
    if re.match(r"^[a-fA-F0-9]{64}$", val):
        return {"valid": True, "indicator_type": "FILE_HASH", "normalized_value": val.lower(), "validation_notes": "Syntactically valid SHA-256 hash"}

    # 4. URL Validation
    if val.startswith("http://") or val.startswith("https://"):
        parsed = urlparse(val)
        if parsed.netloc:
            return {"valid": True, "indicator_type": "URL", "normalized_value": val, "validation_notes": "Syntactically valid URL structure"}

    # 5. Domain Validation
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, val):
        return {"valid": True, "indicator_type": "DOMAIN", "normalized_value": val.lower(), "validation_notes": "Syntactically valid domain name"}

    return {
        "valid": False,
        "indicator_type": "UNKNOWN",
        "normalized_value": val,
        "validation_notes": "Format does not match any recognized defensive security indicator syntax"
    }