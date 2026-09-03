"""Run evtx-sigma-checker against a baseline, splitting rules across parallel workers."""

import argparse
import math
import os
import shutil
import subprocess
import sys
import tempfile


def _link(src: str, dst: str) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def collect_rules(rule_paths: list[str]) -> list[str]:
    rules = []
    for path in rule_paths:
        if not os.path.exists(path):
            print(f"Warning: rule path '{path}' does not exist, skipping")
            continue
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith(".yml"):
                    rules.append(os.path.join(root, f))
    return sorted(rules)


def run(args: argparse.Namespace) -> int:
    rules = collect_rules(args.rule_paths)
    total = len(rules)
    if total == 0:
        print("Error: no rule files found")
        return 1

    workers = args.workers if args.workers is not None else (os.cpu_count() or 2)
    shard_size = math.ceil(total / workers)
    print(f"Found {total} rules, splitting into {workers} shards of ~{shard_size} each")

    tmpdirs = []
    procs = []

    try:
        for shard in range(workers):
            tmpdir = tempfile.mkdtemp()
            tmpdirs.append(tmpdir)

            start = shard * shard_size
            chunk = rules[start : start + shard_size]
            for i, rule in enumerate(chunk):
                _link(os.path.abspath(rule), os.path.join(tmpdir, f"{start + i}.yml"))

            out_file = os.path.join(tempfile.gettempdir(), f"goodlog_findings_{shard}.json")
            cmd = [
                args.checker,
                "--log-source", args.log_source,
                "--evtx-path", args.evtx_path,
                "--rule-path", tmpdir,
            ]
            procs.append((subprocess.Popen(cmd, stdout=open(out_file, "w"), stderr=subprocess.PIPE), out_file))

        errors = []
        for proc, out_file in procs:
            _, stderr = proc.communicate()
            if proc.returncode != 0:
                errors.append(stderr.decode().strip())

        if errors:
            for err in errors:
                print(f"Error: evtx-sigma-checker failed: {err}", file=sys.stderr)
            return 1

        with open(args.output, "w") as out:
            for _, out_file in procs:
                with open(out_file) as f:
                    out.write(f.read())
                os.unlink(out_file)

        print(f"Findings written to {args.output}")
        return 0

    finally:
        for tmpdir in tmpdirs:
            shutil.rmtree(tmpdir, ignore_errors=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evtx-path", required=True, help="Path to baseline EVTX directory")
    parser.add_argument("--checker", default="./evtx-sigma-checker", help="Path to evtx-sigma-checker binary")
    parser.add_argument("--log-source", default="tests/thor.yml", help="Path to thor.yml log source config")
    parser.add_argument(
        "--rule-paths",
        nargs="+",
        default=["rules/windows/", "rules-emerging-threats/", "rules-threat-hunting/"],
        help="Rule directories to scan",
    )
    parser.add_argument("--output", default="findings.json", help="Output file for findings")
    def positive_int(value: str) -> int:
        n = int(value)
        if n < 1:
            raise argparse.ArgumentTypeError(f"workers must be a positive integer, got {n}")
        return n

    parser.add_argument(
        "--workers",
        type=positive_int,
        default=None,
        help="Number of parallel checker processes (default: auto based on CPU count)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run(parse_args()))
