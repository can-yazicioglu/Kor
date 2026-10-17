#!/usr/bin/env python3
"""Generate privacy-safe synthetic login events for Ephemeral Login Sentinel.

This generator uses only the Python standard library. Every identifier and value
is synthetic; it does not read customer data, credentials, IP addresses, or geo data.
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

COLUMNS = [
    "event_id",
    "event_ts_utc",
    "session_token",
    "account_token",
    "attempts_2m",
    "attempts_1h",
    "distinct_accounts_2m",
    "failed_ratio_24h",
    "hour_deviation",
    "typical_weekday",
    "geo_velocity_kmh",
    "network_familiarity",
    "asn_category",
    "device_managed",
    "device_new",
    "is_suspicious",
    "attack_type",
]

def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("--start-utc must include a timezone, e.g. 2025-01-01T00:00:00Z")
    return parsed.astimezone(timezone.utc)


def make_profiles(account_tokens: list[str], rng: random.Random) -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for token in account_tokens:
        # A synthetic 30-day baseline: a preferred hour and usual weekdays.
        preferred_days = set(range(5))
        if rng.random() < 0.22:
            preferred_days.add(rng.choice((5, 6)))
        profiles[token] = {
            "preferred_hour": rng.randint(7, 20),
            "preferred_days": preferred_days,
        }
    return profiles


def timestamp_near_profile(
    start: datetime,
    profile: dict[str, Any],
    rng: random.Random,
    *,
    unusual: bool = False,
) -> datetime:
    """Choose a timestamp within the synthetic 30-day period."""
    target_days = [
        start + timedelta(days=offset)
        for offset in range(30)
        if (start + timedelta(days=offset)).weekday() in profile["preferred_days"]
    ]
    if unusual:
        # Pick a non-preferred weekday and a materially unusual hour.
        target_days = [
            start + timedelta(days=offset)
            for offset in range(30)
            if (start + timedelta(days=offset)).weekday() not in profile["preferred_days"]
        ]
        preferred_hour = int(profile["preferred_hour"])
        unusual_hours = [
            hour for hour in range(24)
            if min(abs(hour - preferred_hour), 24 - abs(hour - preferred_hour)) >= 5
        ]
        hour = rng.choice(unusual_hours)
    else:
        hour = int(profile["preferred_hour"] + rng.choice((-1, 0, 0, 0, 1))) % 24
    if not target_days:
        target_days = [start + timedelta(days=offset) for offset in range(30)]
    day = rng.choice(target_days)
    minute = rng.randrange(60)
    second = rng.randrange(60)
    return day.replace(hour=hour, minute=minute, second=second, microsecond=0)


def profile_features(ts: datetime, profile: dict[str, Any]) -> tuple[int, int]:
    preferred_hour = int(profile["preferred_hour"])
    delta = abs(ts.hour - preferred_hour)
    hour_deviation = min(delta, 24 - delta)
    typical_weekday = int(ts.weekday() in profile["preferred_days"])
    return hour_deviation, typical_weekday


def base_row(
    *,
    ts: datetime,
    account: str,
    profile: dict[str, Any],
    event_number: int,
    rng: random.Random,
    attempts_2m: int,
    attempts_1h: int,
    distinct_accounts_2m: int,
    failed_ratio: float,
    suspicious: int,
    attack_type: str,
    network_familiarity: str | None = None,
    asn_category: str | None = None,
    device_managed: int | None = None,
    device_new: int | None = None,
    geo_velocity: int | None = None,
) -> dict[str, Any]:
    hour_deviation, typical_weekday = profile_features(ts, profile)
    return {
        "event_id": f"evt_{event_number:08d}",
        "event_ts_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        # Deterministic, synthetic opaque session keys; one key per event.
        "session_token": f"ses_{rng.getrandbits(96):024x}",
        "account_token": account,
        "attempts_2m": attempts_2m,
        "attempts_1h": attempts_1h,
        "distinct_accounts_2m": distinct_accounts_2m,
        "failed_ratio_24h": round(min(1.0, max(0.0, failed_ratio)), 3),
        "hour_deviation": hour_deviation,
        "typical_weekday": typical_weekday,
        "geo_velocity_kmh": geo_velocity if geo_velocity is not None else rng.randint(0, 140),
        "network_familiarity": network_familiarity or rng.choices(("familiar", "unfamiliar"), (0.88, 0.12))[0],
        "asn_category": asn_category or rng.choices(
            ("residential", "business", "cloud", "vpn", "unknown"),
            (0.48, 0.29, 0.10, 0.08, 0.05),
        )[0],
        "device_managed": device_managed if device_managed is not None else int(rng.random() < 0.72),
        "device_new": device_new if device_new is not None else int(rng.random() < 0.07),
        "is_suspicious": suspicious,
        "attack_type": attack_type,
    }


def chunks(total: int, low: int, high: int, rng: random.Random) -> list[int]:
    result: list[int] = []
    remaining = total
    while remaining:
        size = min(remaining, rng.randint(low, high))
        result.append(size)
        remaining -= size
    return result


def generate_rows(
    *,
    row_count: int,
    attack_rate: float,
    seed: int,
    start: datetime,
) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    positive_count = round(row_count * attack_rate)
    benign_count = row_count - positive_count

    account_count = max(30, min(3000, row_count // 3 + 1))
    account_tokens = [f"acct_{rng.getrandbits(64):016x}" for _ in range(account_count)]
    # Extremely unlikely, but keep the token pool unique by construction.
    account_tokens = list(dict.fromkeys(account_tokens))
    profiles = make_profiles(account_tokens, rng)
    rows: list[dict[str, Any]] = []

    def add(**kwargs: Any) -> None:
        rows.append(base_row(event_number=len(rows) + 1, rng=rng, **kwargs))

    # Non-positive scenarios include ordinary logins, user mistakes, and novel
    # VPN/device logins whose context alone does not warrant a positive label.
    benign_scenarios = rng.choices(
        ("normal", "user_error", "vpn_new_device"),
        weights=(0.72, 0.16, 0.12),
        k=benign_count,
    )
    for scenario in benign_scenarios:
        account = rng.choice(account_tokens)
        profile = profiles[account]
        if scenario == "normal":
            ts = timestamp_near_profile(start, profile, rng)
            add(
                ts=ts, account=account, profile=profile,
                attempts_2m=1, attempts_1h=rng.randint(1, 4),
                distinct_accounts_2m=1, failed_ratio=rng.uniform(0.0, 0.16),
                suspicious=0, attack_type="normal",
            )
        elif scenario == "user_error":
            ts = timestamp_near_profile(start, profile, rng)
            add(
                ts=ts, account=account, profile=profile,
                attempts_2m=rng.randint(2, 3), attempts_1h=rng.randint(3, 8),
                distinct_accounts_2m=1, failed_ratio=rng.uniform(0.12, 0.48),
                suspicious=0, attack_type="user_error",
                network_familiarity="familiar", device_new=0,
                geo_velocity=rng.randint(0, 100),
            )
        else:
            ts = timestamp_near_profile(start, profile, rng)
            add(
                ts=ts, account=account, profile=profile,
                attempts_2m=1, attempts_1h=rng.randint(1, 4),
                distinct_accounts_2m=1, failed_ratio=rng.uniform(0.0, 0.18),
                suspicious=0, attack_type="vpn_new_device",
                network_familiarity="unfamiliar",
                asn_category=rng.choice(("vpn", "cloud", "residential")),
                device_managed=0, device_new=1,
                geo_velocity=rng.randint(0, 250),
            )

    # Divide the requested number of positive rows deterministically between
    # attack scenarios. The remainder goes to suspicious successful logins.
    brute_count = round(positive_count * 0.40)
    spray_count = round(positive_count * 0.30)
    success_count = positive_count - brute_count - spray_count

    # Brute-force episodes repeatedly target one synthetic account in a short
    # interval. attempt counts are rolling-window aggregates, not passwords.
    for episode_size in chunks(brute_count, 4, 9, rng):
        account = rng.choice(account_tokens)
        profile = profiles[account]
        base_ts = timestamp_near_profile(start, profile, rng, unusual=True)
        count_2m = max(episode_size, rng.randint(episode_size + 1, episode_size + 11))
        count_1h = max(count_2m, count_2m + rng.randint(2, 30))
        for _ in range(episode_size):
            ts = base_ts + timedelta(seconds=rng.randrange(115))
            add(
                ts=ts, account=account, profile=profile,
                attempts_2m=count_2m, attempts_1h=count_1h,
                distinct_accounts_2m=1, failed_ratio=rng.uniform(0.62, 1.0),
                suspicious=1, attack_type="brute_force",
                network_familiarity=rng.choice(("unfamiliar", "unfamiliar", "familiar")),
                asn_category=rng.choice(("cloud", "vpn", "residential", "unknown")),
                device_managed=0, device_new=int(rng.random() < 0.35),
                geo_velocity=rng.randint(0, 600),
            )

    # Spraying episodes cover many distinct accounts in the same two-minute
    # aggregate window, with fewer attempts against each individual account.
    for episode_size in chunks(spray_count, 6, 18, rng):
        episode_accounts = rng.sample(account_tokens, k=min(episode_size, len(account_tokens)))
        base_ts = timestamp_near_profile(start, profiles[episode_accounts[0]], rng, unusual=True)
        for account in episode_accounts:
            profile = profiles[account]
            ts = base_ts + timedelta(seconds=rng.randrange(115))
            add(
                ts=ts, account=account, profile=profile,
                attempts_2m=rng.randint(1, 2), attempts_1h=rng.randint(2, 6),
                distinct_accounts_2m=len(episode_accounts), failed_ratio=rng.uniform(0.48, 0.98),
                suspicious=1, attack_type="password_spraying",
                network_familiarity="unfamiliar",
                asn_category=rng.choice(("cloud", "vpn", "unknown")),
                device_managed=0, device_new=int(rng.random() < 0.2),
                geo_velocity=rng.randint(0, 900),
            )

    # A synthetic suspicious successful-login scenario is represented by new
    # device/network plus unusual context. The fixed schema has no success flag;
    # attack_type remains evaluation metadata, not a model feature.
    for _ in range(success_count):
        account = rng.choice(account_tokens)
        profile = profiles[account]
        ts = timestamp_near_profile(start, profile, rng, unusual=True)
        add(
            ts=ts, account=account, profile=profile,
            attempts_2m=rng.randint(1, 3), attempts_1h=rng.randint(1, 8),
            distinct_accounts_2m=1, failed_ratio=rng.uniform(0.12, 0.72),
            suspicious=1, attack_type="suspicious_success",
            network_familiarity="unfamiliar",
            asn_category=rng.choice(("vpn", "cloud", "residential", "unknown")),
            device_managed=0, device_new=1,
            geo_velocity=rng.randint(500, 6000),
        )

    # Randomize ties and order, then assign event IDs in final chronological order.
    rows.sort(key=lambda row: (row["event_ts_utc"], row["event_id"]))
    for index, row in enumerate(rows, start=1):
        row["event_id"] = f"evt_{index:08d}"
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=10_000, help="number of login event rows (default: 10000)")
    parser.add_argument("--seed", type=int, default=42, help="deterministic random seed (default: 42)")
    parser.add_argument(
        "--attack-rate", type=float, default=0.08,
        help="fraction of rows labeled suspicious, from 0 to 1 (default: 0.08)",
    )
    parser.add_argument(
        "--start-utc", type=parse_utc, default=parse_utc("2025-01-01T00:00:00Z"),
        help="start of the synthetic 30-day timeline, with timezone (default: 2025-01-01T00:00:00Z)",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("data/mvp_synthetic_logins.csv"),
        help="CSV output path (default: data/mvp_synthetic_logins.csv)",
    )
    args = parser.parse_args()
    if args.rows < 1:
        parser.error("--rows must be at least 1")
    if not 0 <= args.attack_rate <= 1:
        parser.error("--attack-rate must be between 0 and 1")

    generated = generate_rows(
        row_count=args.rows,
        attack_rate=args.attack_rate,
        seed=args.seed,
        start=args.start_utc,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(generated)

    positive = sum(int(row["is_suspicious"]) for row in generated)
    print(f"Wrote {len(generated)} synthetic rows to {args.output}")
    print(f"Positive labels: {positive}/{len(generated)} ({positive / len(generated):.2%})")
    print(f"Seed: {args.seed}; attack rate target: {args.attack_rate:.2%}")


if __name__ == "__main__":
    main()
