"""
mitmproxy Addon für Google Gemini API - mit vollständiger Signaturen-Verwaltung
Behält den thought_signature Fix 1:1 aus main.py bei
Mit Integration der AIH Detection-Funktionen
"""

import os
import json
import hashlib
import time
import logging
import sys
import io
from contextlib import redirect_stdout, redirect_stderr
from mitmproxy import http, ctx
from collections import defaultdict, deque

# Import AIH Detection Functions
from AIH.aih import is_gemini_request, is_vscode_chat_request

API_KEY = os.environ.get("GEMINI_API_KEY")
TARGET_MODEL = "gemini-2.0-flash-exp"

# Hash(FunctionName + Args) -> Thought_Signature
signature_store = {}

# Token-Optimierungs-Features

CACHE_TTL = 300  # Response Cache TTL in Sekunden
RATE_LIMIT_WINDOW = 60  # Rate Limit Fenster in Sekunden
RATE_LIMIT_MAX = 30  # Max Requests pro Fenster
MAX_REQUEST_SIZE = 50000  # Max Request Size in Bytes
DUPE_WINDOW = 10  # Deduplication Fenster in Sekunden
MAX_TOKENS = 1000  # Hartes Token-Limit für Requests

# Wie viele vergangene Chat-Messages (non-system) behalten wir maximal als Backlog?
# How many past chat messages (non-system) to keep as backlog
# Increased to 10 per user request
BACKLOG_MESSAGES = 10
# Falls True: System-Nachrichten (role=='system') werden immer behalten
BACKLOG_PRESERVE_SYSTEM = True

# --- Flag: Keine Kürzungen (True = nie kürzen, False = Standardverhalten)
NO_TRUNCATE = False

# Load tools selection config (defaults + overrides + settings)
TOOL_SELECTION = None


def load_tools_selection():
    """Lädt `Payloads/tools_selection.json` falls vorhanden und bereitet
    eine schnelle Lookup-Struktur vor.
    Rückgabe: dict mit keys: defaults.enabled, overrides_map, settings
    """
    global TOOL_SELECTION
    sel_path = os.path.join(os.path.dirname(__file__), "Payloads", "tools_selection.json")
    defaults = {"enabled": True}
    overrides_map = {}
    settings = {"remove_system_instruction": True}
    try:
        if os.path.exists(sel_path):
            with open(sel_path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                if "defaults" in obj and isinstance(obj["defaults"], dict):
                    defaults.update(obj["defaults"])
                if "overrides" in obj and isinstance(obj["overrides"], list):
                    for o in obj["overrides"]:
                        if isinstance(o, dict) and "name" in o and "enabled" in o:
                            overrides_map[o["name"]] = bool(o["enabled"])
                if "settings" in obj and isinstance(obj["settings"], dict):
                    settings.update(obj["settings"])
    except Exception as e:
        ctx.log.warn(f"[!] Fehler beim Laden von tools_selection.json: {e}")

    TOOL_SELECTION = {
        "defaults": defaults,
        "overrides": overrides_map,
        "settings": settings,
    }
    return TOOL_SELECTION


# initialize on import
try:
    load_tools_selection()
except Exception:
    TOOL_SELECTION = {"defaults": {"enabled": True}, "overrides": {}, "settings": {"remove_system_instruction": True}}

# Globale Stores
response_cache = {}  # request_hash -> (response, timestamp)
request_times = defaultdict(deque)  # client_ip -> deque von timestamps
token_usage = defaultdict(int)  # client_ip -> token_count
recent_requests = {}  # request_hash -> timestamp


# ---------- Hilfsfunktionen: robustes JSON & Hashing ----------

def safe_json_loads(s):
    """Versucht JSON zu parsen, gibt bei Fehlern None zurück."""
    try:
        return json.loads(s)
    except Exception:
        return None


def get_call_hash(function_name, function_args):
    """Erzeugt einen stabilen Hash für einen Funktionsaufruf."""
    try:
        if isinstance(function_args, str):
            try:
                function_args = json.loads(function_args)
            except Exception:
                pass

        args_str = json.dumps(function_args, sort_keys=True, ensure_ascii=False)
        unique_string = f"{function_name}::{args_str}"
        return hashlib.md5(unique_string.encode("utf-8")).hexdigest()
    except Exception as e:
        ctx.log.warn(f"[!] Hash Error: {e}")
        return None


def get_request_hash(content: str, headers: dict) -> str:
    """Erzeugt einen Hash für Request-Caching."""
    # Ignoriere zeitabhängige Header für besseres Caching
    relevant_headers = {k: v for k, v in headers.items() 
                       if k.lower() not in ['date', 'timestamp', 'x-request-id', 'request-id']}
    
    hash_input = f"{content}::{json.dumps(relevant_headers, sort_keys=True)}"
    return hashlib.sha256(hash_input.encode()).hexdigest()


def estimate_tokens(text: str) -> int:
    """Schätzt Token-Anzahl (grober Richtwert: ~4 Zeichen pro Token)."""
    return max(1, len(text) // 4)


def intelligent_truncate_json(payload_str: str, max_tokens: int) -> str:
    """
    Intelligente JSON-Kürzung: Versucht, das JSON zu parsen und 
    iterativ Inhalte zu entfernen (contents, candidates, parts), 
    statt einfach den String zu schneiden.
    """
    max_len = max_tokens * 4

    if len(payload_str) <= max_len:
        return payload_str

    try:
        data = json.loads(payload_str)
    except Exception:
        # Not JSON — fallback to simple slice
        return payload_str[:max_len]

    if not isinstance(data, dict):
        return payload_str[:max_len]

    tool = RequestJSONTool()

    # First: try proportional truncation of parts to reduce total chars
    removed = tool.truncate_parts_to_limit(data, max_total_chars=max_len)
    result = json.dumps(data, ensure_ascii=False)
    if len(result) <= max_len:
        return result

    # Second: remove trailing contents entries
    if "contents" in data and isinstance(data["contents"], list):
        while data["contents"] and len(json.dumps(data, ensure_ascii=False)) > max_len:
            data["contents"].pop()
    result = json.dumps(data, ensure_ascii=False)
    if len(result) <= max_len:
        return result

    # Third: remove candidates
    if "candidates" in data and isinstance(data["candidates"], list):
        while data["candidates"] and len(json.dumps(data, ensure_ascii=False)) > max_len:
            data["candidates"].pop()
    result = json.dumps(data, ensure_ascii=False)
    if len(result) <= max_len:
        return result

    # Aggressive: replace each part.text with a short placeholder/prefix until small enough
    parts = list(tool.find_parts_texts(data))
    if parts:
        for path, text in parts:
            # keep only first 40 chars
            new_text = (text[:40].rstrip() + "\n...[truncated]") if len(text) > 40 else text
            tool._set_value_at_path(data, path, new_text)
            if len(json.dumps(data, ensure_ascii=False)) <= max_len:
                return json.dumps(data, ensure_ascii=False)

    # Final fallback: replace all parts with a single marker to guarantee small size
    for path, _ in parts:
        tool._set_value_at_path(data, path, "[TRUNCATED]")
    result = json.dumps(data, ensure_ascii=False)
    if len(result) <= max_len:
        return result

    # If even this doesn't help (extremely unlikely), return a small valid JSON error
    return json.dumps({"error": "Request too large and could not be truncated safely"}, ensure_ascii=False)


def cleanup_old_entries():
    """Räumt veraltete Cache-Einträge und Request-Historie auf."""
    current_time = time.time()
    
    # Response Cache aufräumen
    expired_keys = [k for k, (_, timestamp) in response_cache.items() 
                   if current_time - timestamp > CACHE_TTL]
    for k in expired_keys:
        del response_cache[k]
    
    # Request Times aufräumen
    for client_ip in list(request_times.keys()):
        times = request_times[client_ip]
        while times and current_time - times[0] > RATE_LIMIT_WINDOW:
            times.popleft()
        if not times:
            del request_times[client_ip]
    
    # Recent Requests aufräumen
    expired_requests = [k for k, timestamp in recent_requests.items()
                       if current_time - timestamp > DUPE_WINDOW]
    for k in expired_requests:
        del recent_requests[k]


def is_rate_limited(client_ip: str) -> bool:
    """Prüft ob Client rate-limited ist."""
    current_time = time.time()
    times = request_times[client_ip]
    
    # Alte Einträge entfernen
    while times and current_time - times[0] > RATE_LIMIT_WINDOW:
        times.popleft()
    
    return len(times) >= RATE_LIMIT_MAX


def is_duplicate_request(request_hash: str) -> bool:
    """Prüft ob Request ein Duplikat ist."""
    current_time = time.time()
    if request_hash in recent_requests:
        if current_time - recent_requests[request_hash] < DUPE_WINDOW:
            return True
    recent_requests[request_hash] = current_time
    return False


# ---------- Robust: candidates / parts / content traversieren ----------

def extract_candidates(obj):
    """
    Holt rekursiv alle 'candidates' aus einem JSON-Objekt,
    egal ob es Dict, List oder verschachtelt ist.
    """
    result = []

    if isinstance(obj, dict):
        if "candidates" in obj and isinstance(obj["candidates"], list):
            result.extend(obj["candidates"])
        # zusätzlich rekursiv über alle Values laufen
        for v in obj.values():
            result.extend(extract_candidates(v))

    elif isinstance(obj, list):
        for item in obj:
            result.extend(extract_candidates(item))

    return result


def iter_parts_from_candidate(candidate):
    """
    Iteriert robust über alle parts eines candidates.
    candidate kann Dict oder List sein, content kann Dict oder List sein,
    parts kann Dict oder List sein.
    """
    # Falls candidate eine Liste ist, rekursiv über alle Elemente
    if isinstance(candidate, list):
        for c in candidate:
            yield from iter_parts_from_candidate(c)
        return

    if not isinstance(candidate, dict):
        return

    content = candidate.get("content", [])
    if isinstance(content, dict):
        content = [content]
    elif not isinstance(content, list):
        return

    for c in content:
        if not isinstance(c, dict):
            continue
        parts = c.get("parts", [])
        if isinstance(parts, dict):
            parts = [parts]
        elif not isinstance(parts, list):
            continue

        for p in parts:
            if isinstance(p, dict):
                yield p


    # ---------- Request JSON Inspector / Pruner ----------
    class RequestJSONTool:
        """Hilfs-Klasse zum Analysieren und gezielten Reduzieren von Request-JSONs.

        Funktionen:
        - summarize(data): liefert schnelle Struktur-Übersicht
        - find_parts_texts(data): listet alle `parts[*].text`-Felder mit Pfadangaben
        - strip_marked_sections(data, start_tag, end_tag): entfernt Text zwischen Markern in parts.text
        - truncate_parts_to_limit(data, max_total_chars): sicheres Kürzen der parts.text, valid JSON bleibt erhalten
        - estimate_tokens_from_data(data): verwendet bestehende `estimate_tokens`
        """

        def summarize(self, data: dict) -> dict:
            """Returns a brief summary of where large text lives in the JSON."""
            summary = {
                "top_keys": list(data.keys()) if isinstance(data, dict) else [],
                "num_contents": 0,
                "num_parts": 0,
                "total_chars_in_parts": 0,
                "largest_parts": []  # list of (path, length)
            }
            parts = list(self.find_parts_texts(data))
            summary["num_parts"] = len(parts)
            total = 0
            sizes = []
            for path, text in parts:
                l = len(text)
                total += l
                sizes.append((path, l))
            summary["total_chars_in_parts"] = total
            summary["largest_parts"] = sorted(sizes, key=lambda x: x[1], reverse=True)[:10]
            # contents count if present
            if isinstance(data, dict) and "contents" in data and isinstance(data["contents"], list):
                summary["num_contents"] = len(data["contents"])
            return summary

        def find_parts_texts(self, obj):
            """Yield tuples (path_str, text) for parts[*].text locations.
            Path is a readable string like 'contents[0].parts[2].text'."""
            results = []

            def walk(o, path):
                if isinstance(o, dict):
                    # detect content/parts pattern
                    if "parts" in o and isinstance(o["parts"], list):
                        for i, p in enumerate(o["parts"]):
                            if isinstance(p, dict) and "text" in p and isinstance(p["text"], str):
                                results.append((f"{path}.parts[{i}].text" if path else f"parts[{i}].text", p["text"]))
                            walk(p, f"{path}.parts[{i}]" if path else f"parts[{i}]")
                    for k, v in o.items():
                        walk(v, f"{path}.{k}" if path else k)
                elif isinstance(o, list):
                    for i, item in enumerate(o):
                        walk(item, f"{path}[{i}]")

            walk(obj, "")
            for item in results:
                yield item

        def strip_marked_sections(self, data: dict, start_tag: str, end_tag: str) -> int:
            """Removes text between start_tag and end_tag inside all parts.text entries.
            Returns number of removals.
            """
            removed = 0
            for path, text in self.find_parts_texts(data):
                if start_tag in text and end_tag in text:
                    new_text = ""
                    idx = 0
                    while True:
                        s = text.find(start_tag, idx)
                        if s == -1:
                            new_text += text[idx:]
                            break
                        new_text += text[idx:s]
                        e = text.find(end_tag, s + len(start_tag))
                        if e == -1:
                            # no closing tag; chop remainder
                            removed += 1
                            new_text = new_text
                            break
                        idx = e + len(end_tag)
                        removed += 1
                    # set back into data at path
                    self._set_value_at_path(data, path, new_text)
            return removed

        def truncate_parts_to_limit(self, data: dict, max_total_chars: int, min_per_part: int = 20) -> int:
            """Truncate `parts[*].text` fields in-place so that total chars <= max_total_chars.
            Returns total characters removed.
            Strategy: proportional downscaling of long parts, preserving start and adding a marker.
            """
            parts = list(self.find_parts_texts(data))
            if not parts:
                return 0
            lengths = [len(t) for _, t in parts]
            total = sum(lengths)
            if total <= max_total_chars:
                return 0
            # compute scale factor
            scale = max_total_chars / total
            removed = 0
            for (path, text), orig_len in zip(parts, lengths):
                new_len = max(min_per_part, int(orig_len * scale))
                if new_len >= orig_len:
                    continue
                # keep head portion
                new_text = text[:new_len].rstrip()
                # add marker
                new_text += "\n...[truncated]"
                self._set_value_at_path(data, path, new_text)
                removed += (orig_len - len(new_text))
            return removed

        def estimate_tokens_from_data(self, data: dict) -> int:
            s = json.dumps(data, ensure_ascii=False)
            return estimate_tokens(s)

        def _set_value_at_path(self, data: dict, path: str, value: str):
            """Internal: set value by the path format produced by find_parts_texts.
            e.g. 'contents[0].parts[2].text'"""
            cur = data
            # split by dots but respect indices
            import re
            tokens = re.split(r"\.(?![^\[]*\])", path)
            for i, tok in enumerate(tokens):
                # handle index like name[idx]
                m = re.match(r"([a-zA-Z0-9_\-]*)\[(\d+)\]", tok)
                if m:
                    key = m.group(1)
                    idx = int(m.group(2))
                    if key:
                        cur = cur.get(key, [])
                    if not isinstance(cur, list) or idx >= len(cur):
                        return
                    if i == len(tokens) - 1:
                        # final token: set 'text' or whole item
                        # if token contains .text (rare), handle below
                        cur[idx] = value
                        return
                    cur = cur[idx]
                else:
                    # might be like 'parts[2]' or 'text'
                    m2 = re.match(r"([a-zA-Z0-9_\-]+)\[(\d+)\]", tok)
                    if m2:
                        key = m2.group(1)
                        idx = int(m2.group(2))
                        cur = cur.get(key, [])
                        if not isinstance(cur, list) or idx >= len(cur):
                            return
                        cur = cur[idx]
                    else:
                        # simple key
                        if i == len(tokens) - 1:
                            # final key: set
                            if isinstance(cur, dict) and tok in cur:
                                cur[tok] = value
                            return
                        cur = cur.get(tok, {})



def prune_backlog(data: dict, max_messages: int, preserve_system: bool = True) -> None:
    """Trimmt `data['contents']` so, dass höchstens `max_messages` non-system Nachrichten übrig bleiben.
    System-Nachrichten (role=='system') werden optional behalten und an den Anfang gesetzt.
    Die Funktion ändert `data` in-place.
    """
    if not isinstance(data, dict):
        return
    contents = data.get("contents")
    if not isinstance(contents, list):
        return

    if preserve_system:
        system_msgs = [c for c in contents if c.get("role") == "system"]
        other_msgs = [c for c in contents if c.get("role") != "system"]
    else:
        system_msgs = []
        other_msgs = contents

    if len(other_msgs) <= max_messages:
        data["contents"] = system_msgs + other_msgs
        return

    trimmed = other_msgs[-max_messages:]
    data["contents"] = system_msgs + trimmed


def sanitize_request_for_backlog(data: dict, backlog_messages: int = BACKLOG_MESSAGES) -> None:
    """Entfernt große Meta-Blöcke (Tool-Dokumentation etc.) und kürzt Backlog.
    Ändert `data` in-place.
    """
    if not isinstance(data, dict):
        return

    # Entferne sehr große, unnötige Top-Level Keys. Entferne `systemInstruction`
    # standardmäßig nur, wenn die Auswahl dies verlangt (Settings).
    remove_system = True
    try:
        if TOOL_SELECTION and isinstance(TOOL_SELECTION, dict):
            remove_system = bool(TOOL_SELECTION.get("settings", {}).get("remove_system_instruction", True))
    except Exception:
        remove_system = True

    top_level_remove = ["tools", "toolUseInstructions", "editFileInstructions",
                        "notebookInstructions", "reminderInstructions"]
    if remove_system:
        top_level_remove.insert(0, "systemInstruction")

    for k in top_level_remove:
        if k in data:
            try:
                del data[k]
            except Exception:
                pass

    # Entferne deaktivierte Tools (laut TOOL_SELECTION)
    try:
        if TOOL_SELECTION and "overrides" in TOOL_SELECTION:
            overrides = TOOL_SELECTION.get("overrides", {})
            # Wenn data enthält ein 'tools' Array, filtere dessen Einträge
            if "tools" in data and isinstance(data["tools"], list):
                new_tools = []
                for t in data["tools"]:
                    if isinstance(t, dict):
                        # fall: tool description object with single name
                        name = t.get("name")
                        if name:
                            enabled = overrides.get(name, TOOL_SELECTION["defaults"]["enabled"])
                            if enabled:
                                new_tools.append(t)
                            continue
                        # fall: wrapper that contains 'functionDeclarations'
                        fdecls = t.get("functionDeclarations")
                        if isinstance(fdecls, list):
                            new_fdecls = [fd for fd in fdecls if not (isinstance(fd, dict) and fd.get("name") in overrides and overrides.get(fd.get("name")) is False)]
                            if new_fdecls:
                                t["functionDeclarations"] = new_fdecls
                                new_tools.append(t)
                            # if no functionDeclarations left, skip this tool entry
                            continue
                        # unknown structure: keep by default
                        new_tools.append(t)
                data["tools"] = new_tools
    except Exception as e:
        ctx.log.warn(f"[!] Fehler beim Anwenden der Tools-Selection: {e}")

    # Entferne eingebettete environment/workspace infos innerhalb parts
    tool = RequestJSONTool()
    try:
        tool.strip_marked_sections(data, "<environment_info>", "</environment_info>")
    except Exception:
        pass
    try:
        tool.strip_marked_sections(data, "<workspace_info>", "</workspace_info>")
    except Exception:
        pass

    # Prune contents backlog
    prune_backlog(data, backlog_messages, preserve_system=BACKLOG_PRESERVE_SYSTEM)

# ---------- Signaturen injizieren (vor Request) ----------

def inject_signatures(data):
    """
    Durchläuft die Request-History und ergänzt fehlende thought_signatures
    bei bekannten FunctionCalls.
    """
    if not isinstance(data, dict):
        return 0

    contents = data.get("contents")
    if not isinstance(contents, list):
        return 0

    restored_count = 0

    for content in contents:
        if not isinstance(content, dict):
            continue

        # Wir suchen nur in Model-Antworten der History
        if content.get("role") != "model":
            continue

        parts = content.get("parts", [])
        if isinstance(parts, dict):
            parts = [parts]
        if not isinstance(parts, list):
            continue

        for part in parts:
            if not isinstance(part, dict):
                continue

            if "functionCall" in part and not part.get("thought_signature"):
                fc = part["functionCall"]
                if not isinstance(fc, dict):
                    continue

                f_name = fc.get("name")
                f_args = fc.get("args", {})

                call_hash = get_call_hash(f_name, f_args)
                if call_hash and call_hash in signature_store:
                    original_sig = signature_store[call_hash]
                    part["thought_signature"] = original_sig
                    part["thoughtSignature"] = original_sig
                    restored_count += 1
                    ctx.log.debug(f"[*] 💎 Original-Signatur wiederhergestellt für: {f_name}")
                else:
                    ctx.log.warn(f"[!] Warnung: Keine Signatur für {f_name} im Speicher gefunden.")

    return restored_count


# ---------- Signaturen ernten (nach dem Stream) ----------

def harvest_signatures_from_response_body(full_response_buffer):
    """
    Versucht, aus dem kompletten Response-Body Signaturen zu extrahieren
    und im signature_store zu speichern.
    """
    try:
        response_json = safe_json_loads(full_response_buffer)
        if response_json is None:
            ctx.log.warn("[!] Konnte Response-JSON nicht parsen")
            return

        candidates = extract_candidates(response_json)
        if not candidates:
            ctx.log.debug("[*] Keine candidates im Response gefunden.")
            return

        for cand in candidates:
            for part in iter_parts_from_candidate(cand):
                if "functionCall" not in part:
                    continue

                fc = part["functionCall"]
                if not isinstance(fc, dict):
                    continue

                sig = part.get("thought_signature") or part.get("thoughtSignature")
                if not sig:
                    # ToolCall ohne Signatur – kann vorkommen
                    continue

                name = fc.get("name")
                args = fc.get("args", {})

                c_hash = get_call_hash(name, args)
                if not c_hash:
                    continue

                signature_store[c_hash] = sig
                ctx.log.debug(f"[*] 💾 Signatur gespeichert für: {name}")

    except Exception as e:
        ctx.log.warn(f"[!] Error beim Speichern der Signatur: {e}")


def log_request(flow: http.HTTPFlow):
    """Speichert Request-Details in requests.txt"""
    try:
        payload_dir = os.path.join(os.path.dirname(__file__), "Payloads")
        os.makedirs(payload_dir, exist_ok=True)
        
        req_log_path = os.path.join(payload_dir, "requests.txt")
        
        content = flow.request.content.decode('utf-8', errors='replace') if flow.request.content else ""
        headers = dict(flow.request.headers)
        
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "headers": headers,
            "body": content[:1000] if len(content) > 1000 else content,  # Kürzen zur Lesbarkeit
            "body_size": len(content),
            "full_url": flow.request.url
        }
        
        with open(req_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2))
            f.write("\n" + "=" * 80 + "\n\n")
        
        ctx.log.debug(f"[Gemini] Request geloggt in requests.txt")
        # Zusätzlich: kompletten Request-Body separat speichern (für Debugging)
        try:
            full_dir = os.path.join(payload_dir, "requests_full")
            os.makedirs(full_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            short_hash = hashlib.md5(content.encode('utf-8', errors='replace')).hexdigest()[:8] if content else 'empty'
            full_path = os.path.join(full_dir, f"{ts}_{short_hash}.json")
            # Wenn der Body gültiges JSON ist, schreibe ihn formatiert (mit Zeilenumbrüchen),
            # ansonsten schreibe den Rohstring.
            try:
                parsed = safe_json_loads(content)
                if parsed is not None:
                    # Sanitize before writing: remove metadata, trim backlog
                    try:
                        sanitize_request_for_backlog(parsed, BACKLOG_MESSAGES)
                    except Exception as e:
                        ctx.log.warn(f"[!] Fehler beim Backlog-Sanitizing in log_request: {e}")
                    with open(full_path, "w", encoding="utf-8") as ff:
                        ff.write(json.dumps(parsed, ensure_ascii=False, indent=2))
                else:
                    with open(full_path, "w", encoding="utf-8") as ff:
                        ff.write(content)
            except Exception:
                with open(full_path, "w", encoding="utf-8") as ff:
                    ff.write(content)
            ctx.log.debug(f"[Gemini] Full request body saved: {full_path}")
        except Exception as e:
            ctx.log.warn(f"[!] Fehler beim Speichern des vollständigen Requests: {e}")
    except Exception as e:
        ctx.log.warn(f"[!] Fehler beim Request-Logging: {e}")


def log_response(flow: http.HTTPFlow, response_text: str):
    """Speichert Response-Details in responses.txt"""
    try:
        payload_dir = os.path.join(os.path.dirname(__file__), "Payloads")
        os.makedirs(payload_dir, exist_ok=True)
        
        res_log_path = os.path.join(payload_dir, "responses.txt")
        headers = dict(flow.response.headers) if flow.response else {}
        
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "status_code": flow.response.status_code if flow.response else None,
            "method": flow.request.method,
            "host": flow.request.host,
            "path": flow.request.path,
            "response_headers": headers,
            "body": response_text[:1000] if len(response_text) > 1000 else response_text,  # Kürzen zur Lesbarkeit
            "body_size": len(response_text),
        }
        
        with open(res_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2))
            f.write("\n" + "=" * 80 + "\n\n")
        
        ctx.log.debug(f"[Gemini] Response geloggt in responses.txt")
    except Exception as e:
        ctx.log.warn(f"[!] Fehler beim Response-Logging: {e}")


# ---------- mitmproxy Addon Class ----------

class GeminiProxyAddon:
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.cached_responses = 0
        self.total_tokens_saved = 0
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepted Request: Token-Optimierungen + Signaturen injizieren"""
        
        # Nur Gemini API Requests interessieren uns
        host = flow.request.host
        path = flow.request.path
        headers = dict(flow.request.headers)
        
        if not is_gemini_request(host, path, headers):
            return
        
        # 📝 Request loggen
        log_request(flow)
        
        # Logging & Token-Limit für Gemini-Requests
        payload = flow.request.content.decode('utf-8', errors='replace') if flow.request.content else ''
        token_count = estimate_tokens(payload)
        ctx.log.debug(f"[Gemini] Request erkannt: Host={host}, Path={path}")
        ctx.log.debug(f"[Gemini] Token-Anzahl: {token_count}")
        if not NO_TRUNCATE and token_count > MAX_TOKENS:
            # Intelligente Kürzung: Versuche JSON zu parsen und Inhalte zu entfernen
            payload_cut = intelligent_truncate_json(payload, MAX_TOKENS)
            # Prüfe, ob gekürztes Payload valides JSON ist
            try:
                json.loads(payload_cut)
                flow.request.content = payload_cut.encode('utf-8')
                new_token_count = estimate_tokens(payload_cut)
                ctx.log.debug(f"[Gemini] Payload vom {token_count} auf {new_token_count} Tokens gekürzt.")
                ctx.log.debug(f"[Gemini] Gekürzter Payload: {payload_cut[:500]}...")  # Nur erste 500 chars loggen
            except Exception as e:
                ctx.log.warn(f"[Gemini] Kürzung hätte ungültiges JSON erzeugt: {e}. Request wird geblockt.")
                flow.response = http.Response.make(
                    400, '{"error": "Request zu groß und kann nicht gekürzt werden, ohne ungültiges JSON zu erzeugen."}'.encode("utf-8"),
                    {"Content-Type": "application/json"}
                )
                self.blocked_requests += 1
                return
        else:
            ctx.log.debug(f"[Gemini] Payload-Größe OK: {len(payload)} Bytes")
        self.total_requests += 1
        client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        
        # 🧹 Cleanup alte Einträge (alle 100 Requests)
        if self.total_requests % 100 == 0:
            cleanup_old_entries()
        
        # 🚦 Rate Limiting prüfen
        if is_rate_limited(client_ip):
            ctx.log.warn(f"[!] 🚦 Rate Limit erreicht für {client_ip}")
            flow.response = http.Response.make(
                429, '{"error": "Rate limit exceeded. Zu viele Requests."}'.encode("utf-8"),
                {"Content-Type": "application/json"}
            )
            self.blocked_requests += 1
            return
        
        request_times[client_ip].append(time.time())
        
        # 📏 Request Size prüfen
        if flow.request.content and len(flow.request.content) > MAX_REQUEST_SIZE:
            ctx.log.warn(f"[!] 📏 Request zu groß: {len(flow.request.content)} bytes")
            flow.response = http.Response.make(
                413, '{"error": "Request zu groß. Payload-Limit überschritten."}'.encode("utf-8"),
                {"Content-Type": "application/json"}
            )
            self.blocked_requests += 1
            return
        
        # Request-Body verarbeiten
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8')
                request_hash = get_request_hash(content, headers)
                
                # 🔄 Duplicate Detection
                if is_duplicate_request(request_hash):
                    ctx.log.debug(f"[*] 🔄 Duplikat-Request blockiert: {request_hash[:8]}...")
                    flow.response = http.Response.make(
                        200, '{"error": "Duplicate request blocked"}'.encode("utf-8"),
                        {"Content-Type": "application/json"}
                    )
                    self.blocked_requests += 1
                    return
                
                # 💾 Cache prüfen
                if request_hash in response_cache:
                    cached_response, timestamp = response_cache[request_hash]
                    if time.time() - timestamp < CACHE_TTL:
                        ctx.log.debug(f"[*] 💾 Cache Hit: {request_hash[:8]}...")
                        flow.response = http.Response.make(
                            200, cached_response.encode('utf-8'),
                            {"Content-Type": "application/json", "X-Cache": "HIT"}
                        )
                        self.cached_responses += 1
                        # Token-Einsparung schätzen
                        estimated_tokens = estimate_tokens(content)
                        self.total_tokens_saved += estimated_tokens
                        token_usage[client_ip] -= estimated_tokens  # "negative" usage = Einsparung
                        return
                
                # Request modifizieren (Signaturen etc.)
                data = safe_json_loads(content)
                if data:
                    inject_signatures(data)
                    # Vor dem Serialisieren: sanitize/prune Backlog (entfernt Meta, trims messages)
                    try:
                        sanitize_request_for_backlog(data, BACKLOG_MESSAGES)
                    except Exception as e:
                        ctx.log.warn(f"[!] Fehler beim Backlog-Sanitizing: {e}")
                    modified_content = json.dumps(data).encode('utf-8')
                    flow.request.content = modified_content
                    
                    # Token Usage tracken
                    estimated_tokens = estimate_tokens(content)
                    token_usage[client_ip] += estimated_tokens
                    ctx.log.debug(f"[*] 📊 Request: ~{estimated_tokens} tokens für {client_ip}")
                
                # Store hash für Response Caching
                flow.metadata["request_hash"] = request_hash
                flow.metadata["is_vscode"] = is_vscode_chat_request(headers)
                
            except Exception as e:
                ctx.log.warn(f"[!] Fehler beim Request-Processing: {e}")
        
        # API Key hinzufügen falls nicht vorhanden (verwende `url` statt readonly `pretty_url`)
        try:
            if API_KEY:
                current_url = flow.request.url
                if "key=" not in current_url:
                    sep = "&" if "?" in current_url else "?"
                    flow.request.url = current_url + f"{sep}key={API_KEY}"
        except Exception as e:
            ctx.log.warn(f"[!] Fehler beim Hinzufügen des API-Keys: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercepted Response: Caching + Signaturen ernten"""
        
        # Nur Gemini API Responses interessieren uns
        host = flow.request.host
        path = flow.request.path
        headers = dict(flow.request.headers)
        
        if not is_gemini_request(host, path, headers):
            return
        
        if flow.response and getattr(flow.response, "content", None):
            try:
                response_bytes = getattr(flow.response, "content", None) or b""
                response_text = response_bytes.decode('utf-8', errors='replace')
            except Exception as e:
                ctx.log.warn(f"[Gemini] Fehler beim Decodieren der Response: {e}")
                response_text = ""
        
        # 📝 Response loggen
        log_response(flow, response_text)

        # --- Payload speichern ---
        try:
            payload_dir = os.path.join(os.path.dirname(__file__), "Payloads")
            os.makedirs(payload_dir, exist_ok=True)
            # Finde höchste existierende Nummer
            existing = [int(f.split(".")[0]) for f in os.listdir(payload_dir) if f.endswith(".txt") and f.split(".")[0].isdigit()]
            next_num = max(existing) + 1 if existing else 1
            payload_path = os.path.join(payload_dir, f"{next_num}.txt")
            payload = response_text
            with open(payload_path, "w", encoding="utf-8") as pf:
                pf.write(payload)
            ctx.log.debug(f"[Gemini] Payload gespeichert: {payload_path}")

            # JSON-Request dumpen (append)
            try:
                data = safe_json_loads(payload)
                if data:
                    req_dump_path = os.path.join(payload_dir, "requests.json")
                    with open(req_dump_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(data, ensure_ascii=False))
                        f.write("\n")
            except Exception as e:
                ctx.log.warn(f"[Gemini] Fehler beim JSON-Request-Dump: {e}")
        except Exception as e:
            ctx.log.warn(f"[Gemini] Fehler beim Speichern des Payloads: {e}")

        # Signaturen ernten
        harvest_signatures_from_response_body(response_text)

        # Response Caching (nur bei erfolgreichen Responses)
        try:
            if getattr(flow.response, "status_code", None) == 200 and "request_hash" in flow.metadata:
                request_hash = flow.metadata["request_hash"]
                response_cache[request_hash] = (response_text, time.time())
                ctx.log.debug(f"[*] 💾 Response gecacht: {request_hash[:8]}...")

                # Token Usage für Response tracken
                client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
                response_tokens = estimate_tokens(response_text)
                token_usage[client_ip] += response_tokens

                # Statistiken loggen
                is_vscode = flow.metadata.get("is_vscode", False)
                vscode_tag = "🔵 VSCode" if is_vscode else "🔸 Other"

                ctx.log.debug(
                    f"[*] 📊 {vscode_tag} Response: ~{response_tokens} tokens, "
                    f"Total für {client_ip}: {token_usage[client_ip]}"
                )

                # Alle 50 Responses: Statistik-Summary
                if self.total_requests % 50 == 0:
                    ctx.log.info(
                        f"[*] 📈 STATS: {self.total_requests} requests, "
                        f"{self.blocked_requests} blocked, {self.cached_responses} cached, "
                        f"~{self.total_tokens_saved} tokens gespart"
                    )
        except Exception as e:
            ctx.log.warn(f"[!] Fehler beim Response-Processing: {e}")


# ---------- Addon registrieren ----------

addons = [
    GeminiProxyAddon(),
]


if __name__ == "__main__":
    # Start mitmproxy mit diesem Addon (DumpMaster API verwenden)
    import asyncio
    import sys
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster
    
    print("[DEBUG] Script startet...", flush=True)
    sys.stdout.flush()
    
    async def main():
        print("[DEBUG] main() async-Funktion gestartet", flush=True)
        sys.stdout.flush()
        try:
            opts = options.Options(listen_host="0.0.0.0", listen_port=8080, mode=["regular"])
            print("[DEBUG] Options erstellt", flush=True)
            
            # Silence all loggers completely
            for logger_name in ["mitmproxy", "mitmproxy.proxy", "mitmproxy.tools", "mitmproxy.addons"]:
                logging.getLogger(logger_name).setLevel(logging.CRITICAL)
            logging.getLogger().setLevel(logging.CRITICAL)
            
            # Suppress all mitmproxy stdout/stderr
            devnull = open(os.devnull, 'w')
            
            with redirect_stdout(devnull), redirect_stderr(devnull):
                m = DumpMaster(opts)
                
                # Remove any console addons
                try:
                    console_addon = [a for a in m.addons.chain if "console" in str(type(a).__name__).lower()]
                    for addon in console_addon:
                        m.addons.remove(addon)
                except Exception:
                    pass
            
            devnull.close()
            
            print("[DEBUG] DumpMaster initialisiert", flush=True)
            m.addons.add(GeminiProxyAddon())
            print("[DEBUG] Addon registriert, starte m.run()...", flush=True)
            
            # Run with output suppressed
            devnull = open(os.devnull, 'w')
            try:
                with redirect_stdout(devnull), redirect_stderr(devnull):
                    await m.run()
            finally:
                devnull.close()
                
        except Exception as e:
            print(f"[ERROR] Exception in main(): {e}", flush=True)
            import traceback
            traceback.print_exc()
    
    try:
        print("[DEBUG] Starte asyncio.run(main())...", flush=True)
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[DEBUG] KeyboardInterrupt", flush=True)
    except Exception as e:
        print(f"[ERROR] Exception im Hauptblock: {e}", flush=True)
        import traceback
        traceback.print_exc()

