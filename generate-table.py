import os
import json
import glob
import re
import subprocess
import sys

CONVERSION_FACTOR = 1_000_000
UNIT_STR = "ms"

def extract_n(test_id):
    match = re.search(r'n\s*=\s*(\d+)', test_id)
    if match:
        return int(match.group(1))
    return None

def run_endtoend_and_extract(N, n, t):
    cmd = ["cargo", "run", "--example", "endtoend", "--release", "--", "sign", str(N), str(n), str(t)]
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout + "\n" + result.stderr
        
        match = re.search(r'(?:End:\s*)?Aggregation.*?(\d+\.?\d*)\s*(ms|s|µs|us|ns)', output, re.IGNORECASE)
        if match:
            val = float(match.group(1))
            unit = match.group(2).lower()
            if unit == 's':
                return val * 1000.0
            elif unit == 'ms':
                return val
            elif unit in ('µs', 'us'):
                return val / 1000.0
            elif unit == 'ns':
                return val / 1000000.0
        
        print(f"Warning: cannot parse the time for Aggregation (N={N}, n={n}). Program output:\n{output}")
        return None
    
    except subprocess.CalledProcessError as e:
        print(f"Error: failed to run the command {' '.join(cmd)}\nExit code: {e.returncode}\nError output: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'cargo' command not found, please ensure you are running this script in an environment with Rust installed.")
        sys.exit(1)

def parse_mode():
    if len(sys.argv) >= 2:
        mode = sys.argv[1]
        if mode not in ("fast", "full"):
            print("Usage: generate-table.py {fast|full}", file=sys.stderr)
            sys.exit(1)
        return mode
    return os.environ.get("CSTE_BENCH_MODE", "full")

def main():
    mode = parse_mode()
    results = {}
    
    search_path = os.path.join("target", "criterion", "*", "*", "new", "estimates.json")
    
    for filepath in glob.glob(search_path):
        parts = filepath.split(os.sep)
        group_name = parts[-4]
        bench_id = parts[-3]
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            mean_time_raw = data.get("mean", {}).get("point_estimate", 0)
            
            mean_time = mean_time_raw / CONVERSION_FACTOR
            
            if group_name not in results:
                results[group_name] = {}
            results[group_name][bench_id] = mean_time

    print("Running endtoend tests to collect Aggregation time (Table 2)...")
    print("Note: Depending on the size of N, this may take several minutes.")
    
    table2_cases = [
        (256, 64),
        (1024, 64), (1024, 256),
        (4096, 64), (4096, 256), (4096, 1024),
        (65536, 64), (65536, 256), (65536, 1024), (65536, 4096),
        (1048576, 64), (1048576, 256), (1048576, 1024), (1048576, 4096) # do not recommend; too long to setup
        # The aggregation time only depends on the second value
    ]
    if mode == "fast":
        table2_cases = [(N, n) for N, n in table2_cases if N < 65536]
    
    table2_results = []
    for N, n in table2_cases:
        t = n // 2
        time_ms = run_endtoend_and_extract(N, n, t)
        table2_results.append((N, n, time_ms))

    output_file = "benchmark_results.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Result table\n\n")

        # ---------------------------------------------------------
        # 1. Epoch Table
        # ---------------------------------------------------------
        f.write("## Time to compute the representation of epoch committees (Table 1)\n\n")
        f.write(f"| N | Dyna-hinTS ({UNIT_STR}) | c-STS ({UNIT_STR}) | Overhead |\n")
        f.write("|---|-----------------|------------|----------|\n")
        
        epoch_group = results.get("epoch-repr time", {})
        epoch_n_values = set()
        for test_id in epoch_group:
            n = extract_n(test_id)
            if n is not None:
                epoch_n_values.add(n)
                
        for n in sorted(epoch_n_values):
            dyna = epoch_group.get(f"dyna-hints n = {n}")
            c_sts = epoch_group.get(f"c-sts n = {n}")
            
            dyna_str = f"{dyna:.4f}" if dyna is not None else "-"
            c_sts_str = f"{c_sts:.4f}" if c_sts is not None else "-"
            
            if dyna is not None and c_sts is not None and dyna != 0:
                overhead_str = f"{c_sts / dyna:.4f}"
            else:
                overhead_str = "-"
                
            f.write(f"| {n} | {dyna_str} | {c_sts_str} | {overhead_str} |\n")

        f.write("\n")

        # ---------------------------------------------------------
        # 2. Aggregation Table
        # ---------------------------------------------------------
        f.write("## Aggregation Time (Table 2)\n\n")
        f.write(f"| N | n | This work ({UNIT_STR}) |\n")
        f.write("|---|---|----------------|\n")
        
        for N, n, time_ms in table2_results:
            time_str = f"{time_ms:.4f}" if time_ms is not None else "-"
            f.write(f"| {N} | {n} | {time_str} |\n")
        f.write("\n")

        # ---------------------------------------------------------
        # 3. Hints Table
        # ---------------------------------------------------------
        f.write("## Time to compute a hint for a single party (Table 6)\n\n")
        f.write(f"| N | Dyna-hinTS ({UNIT_STR}) | c-STS ({UNIT_STR}) | Improvement |\n")
        f.write("|---|-----------------|------------|-------------|\n")
        
        hints_group = results.get("single hint generation time", {})
        hints_n_values = set()
        for test_id in hints_group:
            n = extract_n(test_id)
            if n is not None:
                hints_n_values.add(n)
                
        for n in sorted(hints_n_values):
            dyna = hints_group.get(f"generate hint naive n = {n}")
            c_sts = hints_group.get(f"generate hint fast n = {n}")
            
            # we do not evaluate for n >= 2048
            if dyna is None:
                dyna_str = "-"
            else:
                dyna_str = f"{dyna:.4f}"
                
            c_sts_str = f"{c_sts:.4f}" if c_sts is not None else "-"
            
            if dyna is not None and c_sts is not None and c_sts != 0:
                improvement_str = f"{dyna / c_sts:.4f}"
            else:
                improvement_str = "-"
                
            f.write(f"| {n} | {dyna_str} | {c_sts_str} | {improvement_str} |\n")

        f.write("\n")

        # ---------------------------------------------------------
        # 4. Preprocess Table
        # ---------------------------------------------------------
        f.write("## Estimated preprocess time (Table 7)\n\n")
        f.write(f"| N | 1 pairing ({UNIT_STR}) | $msm_1(N)$ ({UNIT_STR}) | $msm_2(N)$ ({UNIT_STR}) | $N+1$ G_1 Add ({UNIT_STR}) | T ({UNIT_STR}) | $T\\times N$ ({UNIT_STR}) | C |\n")
        f.write("|---|--------------|-----------------|-----------------|---------------|--------|------------------|---|\n")
        
        prep_group = results.get("preprocess estimate time", {})
        prep_n_values = set()
        
        pairing_time = prep_group.get("1 pairing", 0.0)
        
        for test_id in prep_group:
            n = extract_n(test_id)
            if n is not None:
                prep_n_values.add(n)
                
        for n in sorted(prep_n_values):
            msm1 = prep_group.get(f"g1 msm n = {n}", 0.0)
            msm2 = prep_group.get(f"g2 msm n = {n}", 0.0)
            add = prep_group.get(f"g1 add n = {n}", 0.0)
            
            t = pairing_time + msm1 + msm2 + add
            t_times_n = t * n
            c = t_times_n / 512
            
            f.write(f"| {n} | {pairing_time:.4f} | {msm1:.4f} | {msm2:.4f} | {add:.4f} | {t:.4f} | {t_times_n:.4f} | {c:.4f} |\n")

    print(f"Data extraction completed, results written to {output_file}")

if __name__ == "__main__":
    main()
