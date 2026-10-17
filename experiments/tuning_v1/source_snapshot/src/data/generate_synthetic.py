#!/usr/bin/env python3
"""Reproducible, entirely synthetic login events; never reads customer data.

Counters are causal rolling aggregates, not independently sampled scores. The
sidecar contains synthetic ground truth for independent audits, never features.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

COLUMNS = [
    "event_id", "event_ts_utc", "session_token", "account_token", "attempts_2m",
    "attempts_1h", "distinct_accounts_2m", "failed_ratio_24h", "hour_deviation",
    "typical_weekday", "geo_velocity_kmh", "network_familiarity", "asn_category",
    "device_managed", "device_new", "is_suspicious", "attack_type",
]
SPLITS = ("fit", "validation", "test")
ASN_CATEGORIES = ("residential", "business", "cloud", "vpn", "unknown")
NORMAL_WEIGHTS = {
    "normal": 0.43, "user_error": 0.20, "vpn_new_device": 0.13,
    "travel_new_device": 0.11, "night_shift": 0.08, "cold_start": 0.05,
}
ATTACK_WEIGHTS = {"brute_force": 0.40, "password_spraying": 0.30, "suspicious_success": 0.30}


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected ISO-8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("--start-utc must include a timezone")
    return parsed.astimezone(timezone.utc)


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def allocate(total: int, weights: dict[str, float]) -> dict[str, int]:
    """Largest remainder allocation preserves the requested exact total."""
    exact = {name: total * weight / sum(weights.values()) for name, weight in weights.items()}
    result = {name: int(value) for name, value in exact.items()}
    order = sorted(exact, key=lambda name: exact[name] - result[name], reverse=True)
    for name in order[:total - sum(result.values())]:
        result[name] += 1
    return result


def generate_dataset(*, row_count: int, attack_rate: float, seed: int,
                     start: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if row_count < 1 or not 0 <= attack_rate <= 1:
        raise ValueError("rows must be positive and attack_rate must be in [0, 1]")
    if start.tzinfo is None:
        raise ValueError("start must include a timezone")
    start = start.astimezone(timezone.utc).replace(microsecond=0)
    rng = random.Random(seed)
    issued_tokens: set[str] = set()

    def token(prefix: str) -> str:
        while True:
            value = f"{prefix}_{rng.getrandbits(128):032x}"
            if value not in issued_tokens:
                issued_tokens.add(value)
                return value

    positive = allocate(round(row_count * attack_rate), dict(zip(SPLITS, (0.6, 0.2, 0.2))))
    negative = allocate(row_count - round(row_count * attack_rate), dict(zip(SPLITS, (0.6, 0.2, 0.2))))
    raw_events: list[dict[str, Any]] = []
    profiles: dict[str, dict[str, Any]] = {}
    warmup: list[dict[str, Any]] = []

    for split_index, split in enumerate(SPLITS):
        # Three separated 8-day observed periods. A full day or more separates
        # cohorts, so no future split supplies a previous split's context.
        begin = start + timedelta(days=split_index * 10)
        cohort_size = max(24, (positive[split] + negative[split]) // 24)
        accounts = [token("acct") for _ in range(cohort_size)]
        for account in accounts:
            profiles[account] = {
                "preferred_hour": rng.randrange(24),
                "preferred_days": sorted(rng.sample(range(7), rng.randint(4, 7))),
                "history_days": 30, "synthetic": True, "split": split,
                "baseline_end_utc": iso(begin - timedelta(seconds=1)),
            }
            # A small explicit synthetic 24h warmup is auditable and cannot
            # contain current/future outcomes. It expires naturally by day 2.
            for _ in range(rng.randint(3, 12)):
                warmup.append({
                    "account_token": account,
                    "event_ts_utc": iso(begin - timedelta(seconds=rng.randint(3601, 86399))),
                    "auth_success": rng.random() > 0.12, "split": split,
                })
        budgets = {**allocate(negative[split], NORMAL_WEIGHTS), **allocate(positive[split], ATTACK_WEIGHTS)}
        for scenario, budget in budgets.items():
            is_attack = scenario in ATTACK_WEIGHTS
            while budget:
                low, high = ((8, 24) if scenario == "brute_force" else
                             (8, 22) if scenario == "password_spraying" else
                             (2, 7) if scenario == "user_error" else
                             (1, 4) if scenario == "suspicious_success" else (1, 5))
                size = min(budget, rng.randint(low, high))
                budget -= size
                episode = token("episode")
                source = token("source")
                account = rng.choice(accounts)
                if scenario == "cold_start":
                    account = token("acct")
                    profiles[account] = {"preferred_hour": None, "preferred_days": [],
                                         "history_days": 0, "synthetic": True, "split": split,
                                         "baseline_end_utc": None}
                profile = profiles[account]
                day = begin + timedelta(days=rng.randrange(8))
                # Benign travel/night work and malicious logins both include
                # ordinary and unusual hours. No class-perfect hour threshold.
                hour = rng.randrange(24)
                if scenario in ("normal", "user_error") and rng.random() < 0.82:
                    hour = (profile["preferred_hour"] + rng.choice((-1, 0, 0, 1))) % 24
                elif scenario == "night_shift":
                    hour = rng.choice((0, 1, 2, 3, 4, 5, 22, 23))
                base_ts = day.replace(hour=hour, minute=rng.randrange(58), second=rng.randrange(30))
                # A non-midnight --start-utc must not place day-zero events
                # before their profile cutoff or synthetic warmup history.
                if base_ts < begin:
                    base_ts += timedelta(days=1)
                # Episode/source lifetime <120s. Some normal shared gateways
                # have multiple accounts, overlapping early spray signatures.
                shared_source = scenario in ("password_spraying", "vpn_new_device")
                episode_accounts = rng.sample(accounts, min(size, len(accounts))) if shared_source else [account]
                session_map: dict[str, str] = {}
                span = rng.randint(30, 110)
                offsets = sorted(rng.sample(range(span + 1), size)) if size <= span + 1 else list(range(size))
                # Context is sampled before labels become CSV metadata. There
                # is deliberate class overlap, including benign high velocity.
                new = int(rng.random() < (0.80 if scenario in ("vpn_new_device", "travel_new_device", "suspicious_success", "cold_start") else 0.18))
                familiar = rng.choices(("familiar", "unfamiliar"), (0.25, 0.75) if is_attack or new else (0.85, 0.15))[0]
                asn = rng.choices(ASN_CATEGORIES, (0.35, 0.28, 0.12, 0.20, 0.05))[0]
                if scenario == "vpn_new_device":
                    asn = "vpn"
                managed = int(rng.random() < (0.25 if is_attack else 0.70))
                if scenario in ("vpn_new_device", "travel_new_device", "suspicious_success"):
                    velocity = round(rng.uniform(450, 6000) if rng.random() < 0.65 else rng.uniform(0, 450), 2)
                else:
                    velocity = round(rng.uniform(600, 4500) if rng.random() < 0.06 else rng.uniform(0, 180), 2)
                missing_context = rng.random() < 0.03
                for index, offset in enumerate(offsets):
                    current_account = episode_accounts[index % len(episode_accounts)]
                    # Simulate cookie rotation during some bursts. Account and
                    # transient-source aggregation do not depend on cookie ID.
                    if current_account not in session_map or (index > 0 and index % 8 == 0):
                        session_map[current_account] = token("ses")
                    if scenario == "suspicious_success":
                        success = True
                    elif scenario in ("brute_force", "password_spraying"):
                        success = rng.random() < 0.04
                    elif scenario == "user_error":
                        success = index == size - 1
                    else:
                        success = rng.random() >= 0.08
                    raw_events.append({
                        "ts": base_ts + timedelta(seconds=offset), "account_token": current_account,
                        "session_token": session_map[current_account], "source_token": source,
                        "episode_id": episode, "split": split, "scenario": scenario,
                        "auth_success": success, "is_suspicious": int(is_attack),
                        "network_familiarity": None if missing_context or scenario == "cold_start" else familiar,
                        "asn_category": asn,
                        "device_managed": None if missing_context or scenario == "cold_start" else managed,
                        "device_new": new, "geo_velocity_kmh": None if missing_context or scenario == "cold_start" else velocity,
                    })
    raw_events.sort(key=lambda event: (event["ts"], event["episode_id"], event["session_token"]))
    warmup.sort(key=lambda event: (event["event_ts_utc"], event["account_token"]))
    previous_outcomes: dict[str, deque[tuple[datetime, bool]]] = defaultdict(deque)
    # Warmup is before each account cohort's first possible observed timestamp.
    for event in warmup:
        previous_outcomes[event["account_token"]].append((parse_utc(event["event_ts_utc"]), event["auth_success"]))
    account_2m: dict[str, deque[datetime]] = defaultdict(deque)
    account_1h: dict[str, deque[datetime]] = defaultdict(deque)
    source_2m: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    rows: list[dict[str, Any]] = []
    manifest_events: dict[str, dict[str, Any]] = {}
    for number, event in enumerate(raw_events, 1):
        ts, account, source = event["ts"], event["account_token"], event["source_token"]
        for queue, seconds in ((account_2m[account], 120), (account_1h[account], 3600)):
            while queue and queue[0] <= ts - timedelta(seconds=seconds):
                queue.popleft()
            queue.append(ts)
        source_queue = source_2m[source]
        while source_queue and source_queue[0][0] <= ts - timedelta(seconds=120):
            source_queue.popleft()
        source_queue.append((ts, account))
        outcomes = previous_outcomes[account]
        while outcomes and outcomes[0][0] <= ts - timedelta(hours=24):
            outcomes.popleft()
        # Include only outcomes already observed in the ordered event stream;
        # current event outcome is appended after feature extraction.
        failure_ratio = round(sum(not outcome for _, outcome in outcomes) / len(outcomes), 6) if outcomes else None
        profile = profiles[account]
        preferred_hour = profile["preferred_hour"]
        delta = abs(ts.hour + ts.minute / 60 + ts.second / 3600 - preferred_hour) if preferred_hour is not None else None
        deviation = round(min(delta, 24 - delta), 6) if delta is not None else None
        event_id = f"evt_{number:08d}"
        rows.append({
            "event_id": event_id, "event_ts_utc": iso(ts),
            "session_token": event["session_token"], "account_token": account,
            "attempts_2m": len(account_2m[account]), "attempts_1h": len(account_1h[account]),
            "distinct_accounts_2m": len({value for _, value in source_queue}),
            "failed_ratio_24h": failure_ratio, "hour_deviation": deviation,
            "typical_weekday": int(ts.weekday() in profile["preferred_days"]) if preferred_hour is not None else None,
            "geo_velocity_kmh": event["geo_velocity_kmh"], "network_familiarity": event["network_familiarity"],
            "asn_category": event["asn_category"], "device_managed": event["device_managed"],
            "device_new": event["device_new"], "is_suspicious": event["is_suspicious"], "attack_type": event["scenario"],
        })
        manifest_events[event_id] = {
            "split": event["split"], "scenario": event["scenario"], "episode_id": event["episode_id"],
            "source_token": source, "auth_success": event["auth_success"],
        }
        outcomes.append((ts, event["auth_success"]))
    manifest = {
        "schema_version": 2, "synthetic": True, "generator_version": "2.0.0",
        "seed": seed, "row_count": row_count, "attack_rate": attack_rate, "start_utc": iso(start),
        "columns": COLUMNS, "split_order": list(SPLITS), "events": manifest_events,
        "warmup_events": warmup, "profiles": profiles,
        "semantics": {
            "attempts_2m": "same account, observed events in (t-120s,t], current event included",
            "attempts_1h": "same account, observed events in (t-3600s,t], current event included",
            "distinct_accounts_2m": "distinct accounts sharing transient source in (t-120s,t], current event included",
            "failed_ratio_24h": "prior known synthetic outcomes in (t-24h,t], current outcome excluded; null if none",
            "tie_order": "CSV event order is causal ingestion order for equal timestamps; no later tied event is visible",
            "hour_deviation": "shortest circular distance from synthetic preferred hour in hours [0,12]",
            "network_familiarity": ["familiar", "unfamiliar", None],
            "asn_category": list(ASN_CATEGORIES), "missing_value_csv": "empty cell; never infer zero",
            "history": "30-day baseline is simulated profile parameters, NOT real observed history; warmup is explicitly synthetic",
            "source_scope": "customer-local transient random source key shared across accounts; no IP or fingerprint",
            "source_ttl_seconds": 120, "session_ttl_seconds": 120,
            "retention": "synthetic CSV/manifest are persistent test fixtures; this generator is not a live production TTL service",
            "split": "account-, episode-, session-, source-disjoint; sequential nonoverlapping time blocks",
        },
        "counts": {"by_split": dict(Counter(e["split"] for e in raw_events)),
                   "by_scenario": dict(Counter(e["scenario"] for e in raw_events)),
                   "suspicious": sum(e["is_suspicious"] for e in raw_events)},
        "limitations": [
            "Entirely synthetic; no real-world effectiveness or calibrated compromise probability is established.",
            "Scenario distributions are authored simulations with overlap, not measured customer behavior.",
            "Cold start or absent recent history creates unknown features; consuming models must abstain or explicitly handle uncertainty.",
            "Source correlation is synthetic. Real customer integration must supply a privacy-preserving transient source key.",
            "Geo velocity is synthetic context sampled without coordinates; VPN jumps are not proof of physical travel.",
        ],
    }
    return rows, manifest


def generate_rows(**kwargs: Any) -> list[dict[str, Any]]:
    """Compatibility helper; use generate_dataset to retain audit provenance."""
    return generate_dataset(**kwargs)[0]


def write_dataset(rows: list[dict[str, Any]], manifest: dict[str, Any], output: Path,
                  manifest_path: Path | None = None) -> tuple[Path, Path]:
    output = Path(output)
    manifest_path = Path(manifest_path) if manifest_path else output.with_suffix(".manifest.json")
    if output.resolve() == manifest_path.resolve():
        raise ValueError("CSV and manifest output paths must differ")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    payload = stream.getvalue().encode("utf-8")
    manifest["csv_sha256"] = hashlib.sha256(payload).hexdigest()
    manifest["csv_file"] = output.name
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return output, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--attack-rate", type=float, default=0.08)
    parser.add_argument("--start-utc", type=parse_utc, default=parse_utc("2025-01-01T00:00:00Z"))
    parser.add_argument("--output", type=Path, default=Path("data/mvp_synthetic_logins.csv"))
    parser.add_argument("--manifest-output", type=Path, default=None)
    args = parser.parse_args()
    if args.rows < 1 or not 0 <= args.attack_rate <= 1:
        parser.error("--rows must be positive and --attack-rate must be in [0, 1]")
    if args.manifest_output and args.output.resolve() == args.manifest_output.resolve():
        parser.error("CSV and manifest output paths must differ")
    rows, manifest = generate_dataset(row_count=args.rows, attack_rate=args.attack_rate,
                                      seed=args.seed, start=args.start_utc)
    output, sidecar = write_dataset(rows, manifest, args.output, args.manifest_output)
    print(f"Wrote {len(rows)} synthetic events to {output}; audit sidecar: {sidecar}")
    print(f"Suspicious={manifest['counts']['suspicious']}; splits={manifest['counts']['by_split']}")
    print(f"CSV SHA-256: {manifest['csv_sha256']}")
    print("Synthetic evaluation only; not evidence of real-world effectiveness.")


if __name__ == "__main__":
    main()
