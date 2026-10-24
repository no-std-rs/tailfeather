#!/usr/bin/env python3
"""Build and measure the identical local flow across features and buffer modes."""
import argparse
import datetime
import json
from pathlib import Path
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--cpu", type=int, help="Pin the benchmark to this Linux CPU")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    samples = []
    for features in ["embassy", "embassy,accelerated-crypto", "std,embassy", "std,embassy,accelerated-crypto"]:
        build = subprocess.run(
            ["cargo", "bench", "--locked", "--manifest-path", str(root / "Cargo.toml"),
             "--no-default-features", "--features", features, "--bench", "throughput",
             "--no-run", "--message-format=json"],
            check=True, text=True, stdout=subprocess.PIPE,
        )
        artifacts = [json.loads(line) for line in build.stdout.splitlines()]
        executable = next(
            item["executable"] for item in artifacts
            if item.get("reason") == "compiler-artifact"
            and item.get("target", {}).get("name") == "throughput"
            and item.get("executable")
        )
        for buffers in (["fixed", "owned"] if features.startswith("std,") else ["fixed"]):
            for layer in ["transport", "mesh"]:
                command = [executable, "--buffers", buffers, "--bytes", str(args.bytes)]
                if layer == "mesh":
                    command.append("--mesh")
                if args.cpu is not None:
                    command = ["taskset", "-c", str(args.cpu), *command]
                run = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE)
                for line in run.stdout.splitlines():
                    sample = json.loads(line)
                    sample["features"] = features
                    samples.append(sample)
                    print(json.dumps(sample), flush=True)
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")), cpu)
    report = {
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cpu": cpu, "pinned_cpu": args.cpu, "platform": platform.platform(),
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "description": "Both endpoints on one worker; 1 warmup + 3 samples; setup excluded; bounded in-memory rings; no NIC/kernel sockets/DERP.",
        "samples": samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
