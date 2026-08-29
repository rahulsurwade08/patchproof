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


def poll_turn(turn_id, timeout=600):
    start = time.time()
    # Hard cap on total turns. The agent may legitimately need 5–7 turns
    # for a full sandbox build → write → exec → read → pull → stop cycle,
    # so the cap is generous. Anything beyond 15 is a runaway loop and we
    # cancel the session so the run doesn't burn tokens indefinitely.
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
                        name = tc.get("name", "?")
                        print("  APPROVE " + name + " " + tc["id"], flush=True)
                        approvals.append({
                            "type": "user.tool_approval",
                            "thread_id": "main",
                            "tool_call_id": tc["id"],
                            "approval": {"status": "allow"}})
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
    """Accept a .json file or KEY=VALUE lines."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    fields = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip()
    return fields


if __name__ == "__main__":
    SID = sys.argv[1]
    msg = None
    if len(sys.argv) >= 3:
        arg2 = sys.argv[2]
        if os.path.isfile(arg2):
            fields = load_fields_from_file(arg2)
            rendered = render_template(fields)
            if rendered:
                msg = rendered
            else:
                # Fallback: build a minimal prompt from the fields
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
