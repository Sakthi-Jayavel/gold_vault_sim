import statistics
import time
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import requests

from gateway.simulated_gateway import simulate_sensor_reading, build_secure_packet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = PROJECT_ROOT / "paper_assets" / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)

SERVER_URL = "http://127.0.0.1:8000/ingest"


def send_one_packet(scenario: Optional[str] = None) -> float:
    """
    Build one reading (with optional scenario), send to server, return latency in ms.
    """
    reading = simulate_sensor_reading(scenario=scenario)
    packet = build_secure_packet(reading)

    start = time.perf_counter()
    resp = requests.post(SERVER_URL, json=packet, timeout=5)
    end = time.perf_counter()

    latency_ms = (end - start) * 1000.0

    try:
        data = resp.json()
        status = data.get("status")
        reasons = data.get("reasons", [])
    except Exception:
        status = f"HTTP {resp.status_code}"
        reasons = [resp.text]

    print(f"[LatencyTest] Scenario={scenario or 'normal'} | Status={status} | Latency={latency_ms:.2f} ms")
    if reasons and status == "BREACH":
        for r in reasons:
            print(f"  - {r}")

    return latency_ms


def run_scenario(name: str, scenario: Optional[str], runs: int = 10):
    print(f"\n=== Scenario: {name} (runs={runs}) ===")
    latencies = []
    for _ in range(runs):
        lat = send_one_packet(scenario=scenario)
        latencies.append(lat)

    avg = statistics.mean(latencies)
    stdev = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    print(f"[Result] {name}: avg latency = {avg:.2f} ms, std = {stdev:.2f} ms")
    return avg, stdev


def main():
    print("[Experiment] End-to-End Latency Test (Gateway -> Server)")

    # IMPORTANT: Make sure uvicorn server.main:app --reload is running before this.

    scenarios = [
        ("Normal (all OK)", None),
        ("Tamper breach", "tamper"),
        ("RFID mismatch", "rfid_mismatch"),
        ("GPS breach", "gps_breach"),
        ("Low purity", "low_purity"),
    ]

    labels = []
    avg_latencies = []

    for name, scen in scenarios:
        avg, stdev = run_scenario(name, scen, runs=5)
        labels.append(name)
        avg_latencies.append(avg)

    print("\n=== Summary (for paper table) ===")
    for name, avg in zip(labels, avg_latencies):
        print(f"{name:20s} | {avg:7.2f} ms")

    # --------- Plot bar chart ---------
    plt.figure()
    x_pos = range(len(labels))
    plt.bar(x_pos, avg_latencies)
    plt.xticks(x_pos, labels, rotation=20, ha="right")
    plt.ylabel("Average latency (ms)")
    plt.title("End-to-End Detection Latency per Scenario")
    plt.grid(axis="y")

    out_path = FIG_DIR / "latency_per_scenario.png"
    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    print(f"\n[Experiment] Saved latency graph to: {out_path}")


if __name__ == "__main__":
    main()
