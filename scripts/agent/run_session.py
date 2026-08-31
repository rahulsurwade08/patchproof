#!/usr/bin/env python3
"""Drive a TrueForge session end-to-end: send the first user prompt (rendered
from agent/prompts/user_template.md + the supplied fields), auto-approve all
tool calls, and stream model text + tool traces to stdout.

Usage:
    scripts/agent/run_session.py <session_id> [user_prompt_file]

If user_prompt_file is omitted, the second positional arg is treated as a
literal prompt string (legacy). With a file, the template is rendered with
the JSON/KEY=VALUE content of the file (or a .json sidecar).

Exit 0 when the session reaches a terminal state (done/error/cancelled).
"""
import http.client
import json
import os
import re
import sys
import time

HOST, PORT = "[::1]", 8790
TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "agent", "prompts", "user_template.md")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def http_get(path):
    c = http.client.HTTPConnection(HOST, PORT, timeout=60)
    c.request("GET", "/api/v1" + path)
    r = c.getresponse()
    data = r.read()
    c.close()
    return json.loads(data)


TURN_COUNT = [0]
AUTO_APPROVE_ALL = [False]


def http_post_sse(path, body_data):
    c = http.client.HTTPConnection(HOST, PORT, timeout=300)
    body = json.dumps(body_data).encode()
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    c.request("POST", "/api/v1" + path, body=body, headers=headers)
    r = c.getresponse()
    raw_parts = []
    while True:
        chunk = r.read(4096)
        if not chunk:
            break
        raw_parts.append(chunk)
    c.close()
    raw = b"".join(raw_parts).decode("utf-8", errors="replace")
    m = re.search(r'"turn_id"\s*:\s*"([^"]+)"', raw)
    return (m.group(1) if m else None, raw)


def render_template(fields):
    """Render agent/prompts/user_template.md by substituting {{key}} placeholders."""
    try:
        with open(TEMPLATE_PATH, encoding="utf-8") as fh:
            tmpl = fh.read()
    except OSError:
        return None
    for k, v in fields.items():
        tmpl = tmpl.replace("{{" + k + "}}", str(v))
    return tmpl


def send_turn(prev, msg=None, approvals=None, is_first=False):
    inp = []
    if msg:
        inp.append({"type": "user.message", "content": msg})
    if approvals:
        inp.extend(approvals)
    body = {"input": inp}
    if not is_first:
        body["previous_turn_id"] = prev
    return http_post_sse("/sessions/" + SID + "/turns", body)


def fetch_model_messages_for_turn(turn_id):
    """Return all model.message events for a turn, keyed by their ID."""
    try:
        d = http_get("/sessions/" + SID + "/turns/" + turn_id + "/events")
        events = d.get("data", [])
    except Exception:
        return {}
    result = {}
    for ev in events:
        ev_data = ev.get("event", {})
        if ev_data.get("type") == "model.message" and ev_data.get("tool_calls"):
            result[ev_data["id"]] = ev_data
        for tc in ev_data.get("tool_calls", []):
            func = tc.get("function", {})
            args_str = func.get("arguments", "{}")
            try:
                args = json.loads(args_str)
            except Exception:
                args = {}
            inp = args.get("input", {})
            mcp = inp.get("mcp_server", "?")
            tname = inp.get("tool_name", "?")
            result[tc["id"]] = {"mcp": mcp, "tool": tname}
    return result


def fetch_tool_call_info(call_id):
    """Look up tool call details from session events by tool_call.id."""
    try:
        d = http_get("/sessions/" + SID + "/events?limit=100")
        events = d.get("data", [])
    except Exception:
        return {}
    for ev in events:
        ev_data = ev.get("event", {})
        if ev_data.get("type") != "model.message":
            continue
        for tc in ev_data.get("tool_calls", []):
            if tc.get("id") == call_id:
                func = tc.get("function", {})
                args_str = func.get("arguments", "{}")
                try:
                    args = json.loads(args_str)
                except Exception:
                    args = {}
                inp = args.get("input", {})
                return {
                    "mcp": inp.get("mcp_server", "?"),
                    "tool": inp.get("tool_name", "?"),
                    "params": {k: v for k, v in inp.items()
                               if k not in ("mcp_server", "tool_name")}}
    return {}


def poll_turn(turn_id, timeout=600):
    start = time.time()
    TURN_LIMIT = 15
    if TURN_COUNT[0] >= TURN_LIMIT:
        print("  TURN LIMIT REACHED (" + str(TURN_LIMIT) + ")", flush=True)
        try:
            http_post_sse("/sessions/" + SID + "/cancel", {})
        except Exception:
            pass
        return
    while time.time() - start < timeout:
        time.sleep(8)
        try:
            d = http_get("/sessions/" + SID + "/turns/" + turn_id)
        except Exception as e:
            print("  poll err:", e)
            continue
        state = d["data"]["state"]
        status = state.get("status", "")
        tokens = state.get("metrics", {}).get("total_tokens", "")
        print("  status=" + status + " tokens=" + str(tokens), flush=True)
        write_telemetry(turn_id, status, tokens)
        if status in ("done", "error", "cancelled"):
            actions = state.get("required_actions", [])
            if actions and status == "done":
                approvals = []
                for a in actions:
                    for tc in a.get("tool_calls", []):
                        cid = tc["id"]
                        info = fetch_tool_call_info(cid)
                        mcp = info.get("mcp", "?")
                        tname = info.get("tool", "call_tool")
                        params = info.get("params", {})
                        short = {k: (str(v)[:60] if not isinstance(v, str) else v[:60])
                                 for k, v in params.items()}
                        print(f"  ? APPROVE [{mcp}] {tname}({short})", flush=True)
                        if AUTO_APPROVE_ALL[0]:
                            status_val = "allow"
                            print(f"  -> auto-allowed", flush=True)
                        else:
                            while True:
                                try:
                                    reply = input("  [y]es / [n]o / [a]ll-yes / [q]uit: ").strip().lower()
                                except (EOFError, KeyboardInterrupt):
                                    reply = "q"
                                if reply in ("y", ""):
                                    status_val = "allow"
                                    break
                                elif reply == "n":
                                    status_val = "deny"
                                    break
                                elif reply == "a":
                                    status_val = "allow"
                                    AUTO_APPROVE_ALL[0] = True
                                    break
                                elif reply == "q":
                                    print("  Quitting.", flush=True)
                                    return
                                else:
                                    print("  Invalid. y / n / a / q", flush=True)
                        approvals.append({
                            "type": "user.tool_approval",
                            "thread_id": "main",
                            "tool_call_id": cid,
                            "approval": {"status": status_val}})
                if approvals:
                    nt, _ = send_turn(turn_id, approvals=approvals, is_first=False)
                    TURN_COUNT[0] += 1
                    print("  next turn " + str(TURN_COUNT[0]) + ": " + str(nt), flush=True)
                    if nt:
                        poll_turn(nt, timeout=timeout)
            else:
                print("  STOP: " + status, flush=True)
                evs = http_get("/sessions/" + SID + "/turns/" + turn_id + "/events").get("data", [])
                for e in evs:
                    if e.get("type") == "model.message":
                        c = e.get("content", "")
                        if isinstance(c, list):
                            for p in c:
                                if p.get("type") == "text" and p.get("text"):
                                    print("---MODEL---", flush=True)
                                    print(p["text"], flush=True)
                        elif isinstance(c, str) and c:
                            print("---MODEL---", flush=True)
                            print(c, flush=True)
            return


def write_telemetry(turn_id, status, tokens):
    """Append per-turn telemetry to data/output/.patchproof/runs/<sid>.jsonl.
    Lets us graph token usage regressions and turn counts across runs."""
    out_dir = os.path.join(REPO_ROOT, "data", "output", ".patchproof", "runs")
    os.makedirs(out_dir, exist_ok=True)
    line = json.dumps({"sid": SID, "turn": turn_id, "status": status,
                       "tokens": tokens, "ts": time.time()})
    with open(os.path.join(out_dir, SID + ".jsonl"), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def load_fields_from_file(path):
    """Accept a .json file or KEY=VALUE / key:value lines."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    fields = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
            elif ":" in line:
                k, v = line.split(":", 1)
            else:
                continue
            fields[k.strip()] = v.strip()
    return fields


if __name__ == "__main__":
    auto_approve = "--auto" in sys.argv
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    SID = sys.argv[1] if len(sys.argv) >= 2 else None
    if not SID:
        print("Usage: run_session.py <session_id> [--auto] [--help]")
        sys.exit(1)
    AUTO_APPROVE_ALL[0] = auto_approve
    if auto_approve:
        print("Auto-approve mode: --all-yes set", flush=True)

    msg = None
    if len(sys.argv) >= 3:
        arg2 = sys.argv[2]
        if not arg2.startswith("--"):
            if os.path.isfile(arg2):
                fields = load_fields_from_file(arg2)
                rendered = render_template(fields)
                if rendered:
                    msg = rendered
                else:
                    lines = ["# Triage request"]
                    for k, v in fields.items():
                        lines.append(k + ": " + v)
                    msg = "\n".join(lines)
            else:
                msg = arg2
    if not msg:
        msg = "Continue."

    print("Session: " + SID, flush=True)
    tid, _ = send_turn(None, msg=msg, is_first=True)
    print("Turn 1: " + str(tid), flush=True)
    if tid:
        poll_turn(tid)
