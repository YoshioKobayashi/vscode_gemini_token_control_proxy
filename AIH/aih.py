def is_vscode_chat_request(headers: dict) -> bool:
    """
    Erkenne VS Code Chat / Copilot / VS Code AI Requests.
    headers: dict mit HTTP-Headern (case-insensitive keys empfohlen)
    """

    ua = headers.get("User-Agent", "").lower()

    # 1. VS Code typische User-Agents
    vscode_markers = [
        "vscode",
        "code/",
        "vscode-win32",
        "vscode-web",
        "electron",
        "vscode-agent",
    ]

    if any(marker in ua for marker in vscode_markers):
        return True

    # 2. Copilot / MS AI spezifische Header
    ms_headers = [
        "x-ms-client-request-id",
        "x-ms-useragent",
        "x-ms-correlation-id",
        "x-ms-copilot",
    ]

    if any(h.lower() in (k.lower() for k in headers.keys()) for h in ms_headers):
        return True

    # 3. Accept-Header von VS Code Chat sind oft extrem breit
    accept = headers.get("Accept", "")
    if "application/json" in accept and "*/*" in accept:
        # nicht eindeutig, aber häufig
        return True

    return False

def is_gemini_request(host: str, path: str, headers: dict) -> bool:
    """
    Erkenne Requests an die Google Gemini API.
    host: Hostname aus dem HTTP-Request
    path: Request-Pfad
    headers: HTTP-Header
    """

    host = host.lower()
    path = path.lower()

    # 1. Offizielle Google Gemini API
    if "generativelanguage.googleapis.com" in host:
        return True

    # 2. Google AI Studio / Vertex AI (OpenAI-kompatibel)
    if "aistudio.googleapis.com" in host:
        return True

    # 3. OpenAI-kompatible Gemini-Proxys
    openai_like_paths = [
        "/v1/chat/completions",
        "/v1/completions",
        "/v1beta/openai",
    ]

    if any(path.startswith(p) for p in openai_like_paths):
        # zusätzliche Absicherung: API-Key-Header
        if "x-goog-api-key" in (k.lower() for k in headers.keys()):
            return True
        if "authorization" in (k.lower() for k in headers.keys()):
            return True

    # 4. Gemini Modellnamen im Payload (optional)
    # Nur wenn du Body-Inspection willst
    # (hier nicht implementiert, aber möglich)

    return False