import bleach

def sanitize_string(val: str) -> str:
    if not val:
        return ""
    return bleach.clean(val.strip())