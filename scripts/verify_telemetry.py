"""Verify that required Windows telemetry reaches the Wazuh indexer (Gate A).

Checks the archives index for Sysmon 1/10/11/12/13, PowerShell 4104 and
Security 4688 from the lab victim inside a recent window, then prints the
real indexed field names (with mapping types) from one sample of each.

Exit codes: 0 = all present, 1 = some missing, 2 = config/connectivity/no data.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import urllib3
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]

SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
SECURITY = "Security"

SYSMON_FILTER_HINT = (
    "may be filtered by the sysmon-modular config: retry with --minutes 60, "
    "inspect `Sysmon64.exe -c`, and record a gap if confirmed"
)


@dataclass(frozen=True)
class Check:
    label: str
    channel: str
    event_id: str
    hint: str


CHECKS = [
    Check("Sysmon 1 ProcessCreate", SYSMON, "1",
          "Sysmon channel not collected? check agent ossec.conf localfile and ossec.log 'Analyzing event log'"),
    Check("Sysmon 10 ProcessAccess", SYSMON, "10", SYSMON_FILTER_HINT),
    Check("Sysmon 11 FileCreate", SYSMON, "11", SYSMON_FILTER_HINT),
    Check("Sysmon 12 Registry create/delete", SYSMON, "12", SYSMON_FILTER_HINT),
    Check("Sysmon 13 Registry value set", SYSMON, "13", SYSMON_FILTER_HINT),
    Check("PowerShell 4104 ScriptBlock", POWERSHELL, "4104",
          "check ScriptBlockLogging policy and the PowerShell/Operational localfile (lab-setup.md s4, s7)"),
    Check("Security 4688 ProcessCreation", SECURITY, "4688",
          "check auditpol Process Creation and the Security localfile <query> (lab-setup.md s5, s7)"),
]

# Wazuh's documented names; confirmed (or replaced) at runtime via _field_caps.
AGENT_FIELD = "agent.name"
TIME_FIELD = "@timestamp"
PREFERRED_EVENT_ID = "data.win.system.eventID"
PREFERRED_CHANNEL = "data.win.system.channel"
SOURCE_TIME_FIELD = "data.win.system.systemTime"

# Fields shown from each sample: everything under data.win.* plus these.
META_FIELDS = ("@timestamp", "timestamp", "id", "agent.id", "agent.name", "decoder.name", "location")
CAPS_PATTERNS = ["data.win.*", "agent.*", "@timestamp", "timestamp", "id", "decoder.name", "location"]

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?$")


class IndexerError(RuntimeError):
    pass


class Indexer:
    def __init__(self, url: str, user: str, password: str, verify: bool | str) -> None:
        self.base = url.rstrip("/")
        self.http = requests.Session()
        self.http.auth = (user, password)
        self.http.verify = verify

    def _req(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self.http.request(method, f"{self.base}/{path.lstrip('/')}", timeout=30, **kwargs)
        if resp.status_code >= 400:
            raise IndexerError(f"{method} /{path.lstrip('/')} -> HTTP {resp.status_code}: {resp.text[:300]}")
        return resp.json()

    def info(self) -> dict:
        return self._req("GET", "/")

    def indices(self, pattern: str) -> list[dict]:
        return self._req("GET", f"_cat/indices/{pattern}",
                         params={"format": "json", "h": "index,docs.count,store.size", "s": "index"})

    def field_caps(self, index: str, fields: list[str]) -> dict:
        return self._req("GET", f"{index}/_field_caps",
                         params={"fields": ",".join(fields), "ignore_unavailable": "true"})

    def search(self, index: str, body: dict) -> dict:
        return self._req("POST", f"{index}/_search", json=body)


def tls_verify(raw: str | None) -> bool | str:
    value = (raw or "true").strip()
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no"}:
        return False
    return value  # path to CA bundle


def field_types(caps: dict) -> dict[str, str]:
    return {name: "|".join(sorted(types)) for name, types in caps.get("fields", {}).items()}


def resolve_field(types: dict[str, str], preferred: str, leaf: str) -> str | None:
    if preferred in types:
        return preferred
    leaf = "." + leaf.lower()
    candidates = sorted(f for f in types if f.startswith("data.win.") and f.lower().endswith(leaf))
    return candidates[0] if candidates else None


def exact(field: str, value: str, ftype: str) -> dict:
    kinds = set(ftype.split("|"))
    if "text" in kinds:
        return {"match_phrase": {field: value}}
    if kinds <= {"keyword", "constant_keyword", "wildcard"}:
        return {"term": {field: {"value": value, "case_insensitive": True}}}
    return {"term": {field: value}}


def total_hits(res: dict) -> int:
    total = res["hits"]["total"]
    return total["value"] if isinstance(total, dict) else int(total)


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {prefix: obj}
    out: dict[str, Any] = {}
    for key, value in obj.items():
        out.update(flatten(value, f"{prefix}.{key}" if prefix else key))
    return out


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    m = TS.match(value.strip())
    if not m:
        return None
    base, frac, tz = m.groups()
    frac = (frac or "0")[:6].ljust(6, "0")
    if tz in (None, "Z"):
        tz = "+00:00"
    elif ":" not in tz:
        tz = f"{tz[:3]}:{tz[3:]}"
    return datetime.fromisoformat(f"{base}.{frac}{tz}")


def ingest_lag(flat: dict[str, Any]) -> float | None:
    ingest, source = parse_ts(flat.get(TIME_FIELD)), parse_ts(flat.get(SOURCE_TIME_FIELD))
    if ingest is None or source is None:
        return None
    return (ingest - source).total_seconds()


def show(value: Any, max_len: int) -> str:
    text = IPV4.sub("x.x.x.x", str(value)).replace("\r", "\\r").replace("\n", "\\n")
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def agent_names(ix: Indexer, index: str, window: dict) -> list[str]:
    res = ix.search(index, {
        "size": 0,
        "query": {"bool": {"filter": [window]}},
        "aggs": {"agents": {"terms": {"field": AGENT_FIELD, "size": 25}}},
    })
    return [b["key"] for b in res.get("aggregations", {}).get("agents", {}).get("buckets", [])]


def run(ix: Indexer, index: str, agent: str, minutes: int, show_values: bool, max_len: int) -> int:
    info = ix.info()
    ver = info.get("version", {})
    print(f"Indexer: {ver.get('distribution', 'elasticsearch')} {ver.get('number')}  cluster={info.get('cluster_name')}")

    rows = ix.indices(index)
    if not rows:
        print(f"ERROR: no indices match '{index}'. Archives not enabled? See docs/lab-setup.md section 8.")
        return 2
    newest = rows[-1]
    print(f"Indices matching {index}: {len(rows)}  newest={newest['index']} docs={newest['docs.count']}")

    types = field_types(ix.field_caps(index, CAPS_PATTERNS + ["*eventID*", "*channel*"]))
    eid_field = resolve_field(types, PREFERRED_EVENT_ID, "eventID")
    chan_field = resolve_field(types, PREFERRED_CHANNEL, "channel")
    print(f"Resolved fields: event_id={eid_field} [{types.get(eid_field or '', '?')}]  "
          f"channel={chan_field} [{types.get(chan_field or '', '?')}]  "
          f"agent={AGENT_FIELD} [{types.get(AGENT_FIELD, '?')}]")
    if not eid_field or not chan_field:
        print("ERROR: no data.win.* eventID/channel field in the index mapping. "
              "Windows eventchannel events are not being decoded/indexed.")
        return 2

    window = {"range": {TIME_FIELD: {"gte": f"now-{minutes}m"}}}
    agent_clause = exact(AGENT_FIELD, agent, types.get(AGENT_FIELD, ""))
    agent_total = total_hits(ix.search(index, {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [window, agent_clause]}},
    }))
    print(f"Agent '{agent}': {agent_total} archived events in the last {minutes}m")
    if agent_total == 0:
        seen = agent_names(ix, index, window)
        print(f"ERROR: no events from agent '{agent}'. agent.name values in window: {seen or 'none'}")
        return 2

    results: list[tuple[Check, int, dict | None]] = []
    for chk in CHECKS:
        res = ix.search(index, {
            "size": 1,
            "track_total_hits": True,
            "sort": [{TIME_FIELD: "desc"}],
            "query": {"bool": {"filter": [
                window,
                agent_clause,
                exact(chan_field, chk.channel, types.get(chan_field, "")),
                exact(eid_field, chk.event_id, types.get(eid_field, "")),
            ]}},
        })
        hits = res["hits"]["hits"]
        results.append((chk, total_hits(res), hits[0] if hits else None))

    print(f"\n{'CHECK':<36} {'RESULT':<6} {'COUNT':>7}  {'LATEST ' + TIME_FIELD:<30} {'LAG s':>7}")
    for chk, count, hit in results:
        flat = flatten(hit["_source"]) if hit else {}
        lag = ingest_lag(flat)
        print(f"{chk.label:<36} {'PASS' if count else 'MISS':<6} {count:>7}  "
              f"{str(flat.get(TIME_FIELD, '-')):<30} {f'{lag:.2f}' if lag is not None else '-':>7}")

    lags = [lag for _, _, hit in results if hit and (lag := ingest_lag(flatten(hit["_source"]))) is not None]
    if any(lag < 0 for lag in lags):
        print("WARNING: negative lag: victim clock is ahead of the manager. Fix time sync (lab-setup.md s6).")

    for chk, count, hit in results:
        if not hit:
            continue
        flat = flatten(hit["_source"])
        keys = [k for k in META_FIELDS if k in flat] + sorted(k for k in flat if k.startswith("data.win."))
        print(f"\n== {chk.label}  (_index={hit['_index']})")
        for key in keys:
            line = f"  {key:<48} {types.get(key, 'UNMAPPED'):<18}"
            print(line + (f" {show(flat[key], max_len)}" if show_values else ""))

    missing = [chk for chk, count, _ in results if not count]
    print()
    if not missing:
        print(f"OK: all {len(CHECKS)} event types present in the last {minutes}m.")
        return 0
    print(f"MISSING {len(missing)}/{len(CHECKS)}:")
    for chk in missing:
        print(f"  - {chk.label}: {chk.hint}")
    return 1


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--minutes", type=int, default=10, help="lookback window (default 10)")
    p.add_argument("--index", default="wazuh-archives-*", help="index pattern (default wazuh-archives-*)")
    p.add_argument("--agent", help="agent name (default LAB_VICTIM_HOSTNAME from .env)")
    p.add_argument("--no-values", action="store_true", help="print field names/types only")
    p.add_argument("--max-value-len", type=int, default=100, help="truncate sample values (default 100)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    args = parse_args(argv)
    load_dotenv(REPO_ROOT / ".env")

    required = ("WAZUH_INDEXER_URL", "WAZUH_USER", "WAZUH_PASS", "LAB_VICTIM_HOSTNAME")
    missing = [name for name in required if not os.environ.get(name)]
    if missing and not (missing == ["LAB_VICTIM_HOSTNAME"] and args.agent):
        print(f"ERROR: missing in .env: {', '.join(missing)} (copy .env.example to .env)", file=sys.stderr)
        return 2

    verify = tls_verify(os.environ.get("TLS_VERIFY"))
    if isinstance(verify, str) and not Path(verify).is_file():
        print(f"ERROR: TLS_VERIFY is neither true/false nor an existing CA file: {verify}", file=sys.stderr)
        return 2
    if verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("NOTE: TLS verification disabled (TLS_VERIFY=false)")

    ix = Indexer(os.environ["WAZUH_INDEXER_URL"], os.environ["WAZUH_USER"], os.environ["WAZUH_PASS"], verify)
    try:
        return run(ix, args.index, args.agent or os.environ["LAB_VICTIM_HOSTNAME"],
                   args.minutes, not args.no_values, args.max_value_len)
    except (requests.RequestException, IndexerError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
