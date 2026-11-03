import re
import sys


def to_seconds(value: float, unit: str) -> float:
    return {
        "ns": value * 1e-9,
        "us": value * 1e-6,
        "µs": value * 1e-6,
        "ms": value * 1e-3,
        "s": value,
    }[unit]


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python find-poly-threshold.py <benchmark-log>", file=sys.stderr)
        return 2

    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        text = handle.read()

    samples = {}
    benchmark_pattern = re.compile(
        r"polynomial product/hybrid/4096/threshold=(\d+)/4096"
    )
    timing_pattern = re.compile(
        r"time:\s*\[\s*([\d.]+)\s*(ns|us|µs|ms|s)\s+"
        r"([\d.]+)\s*(ns|us|µs|ms|s)\s+([\d.]+)\s*(ns|us|µs|ms|s)\s*\]"
    )

    current_threshold = None
    for line in text.splitlines():
        match = benchmark_pattern.search(line)
        if match:
            current_threshold = int(match.group(1))
            continue

        match = timing_pattern.search(line)
        if match and current_threshold is not None:
            if match.group(2) == match.group(4) == match.group(6):
                unit = match.group(4)
                samples[current_threshold] = to_seconds(float(match.group(3)), unit)
            current_threshold = None

    if not samples:
        print("Could not determine the polynomial product threshold", file=sys.stderr)
        return 1

    best_threshold = min(samples, key=samples.get)
    print(best_threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
