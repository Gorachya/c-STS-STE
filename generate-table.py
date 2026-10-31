import os
import json
import glob
import re
import sys

CONVERSION_FACTOR = 1_000_000
UNIT_STR = "ms"

def extract_n(test_id):
    match = re.search(r'n\s*=\s*(\d+)', test_id)
    if match:
        return int(match.group(1))
    return None

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

    output_file = "benchmark_results.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Result table\n\n")

        # ---------------------------------------------------------
        # 1. Epoch Table
        # ---------------------------------------------------------
        f.write("## Time to compute the representation of epoch committees (Table 1)\n\n")
        f.write(f"| n | Dyna-hinTS ({UNIT_STR}) | c-STS ({UNIT_STR}) | Overhead |\n")
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
        # Fixed c-STS Verification Time
        # ---------------------------------------------------------
        f.write("## c-STS Verification Time (fixed n=4096, t=2048)\n\n")
        f.write(f"| n | t | Time ({UNIT_STR}) |\n")
        f.write("|---|---|------|\n")
        verification_time = results.get("c-sts verification time", {}).get("n=4096,t=2048")
        verification_time_str = f"{verification_time:.4f}" if verification_time is not None else "-"
        f.write(f"| 4096 | 2048 | {verification_time_str} |\n")
        f.write("\n")

        # ---------------------------------------------------------
        # 2. Aggregation Table
        # ---------------------------------------------------------
        f.write("## Aggregation Time (Table 2)\n\n")
        f.write(f"| n | This work ({UNIT_STR}) |\n")
        f.write("|---|----------------|\n")

        aggregation_group = results.get("aggregation time", {})
        aggregation_n_values = sorted({
            n for test_id in aggregation_group
            if (n := extract_n(test_id)) is not None
        })
        for n in aggregation_n_values:
            time_ms = aggregation_group.get(f"n={n},t={n // 2}")
            time_str = f"{time_ms:.4f}" if time_ms is not None else "-"
            f.write(f"| {n} | {time_str} |\n")
        f.write("\n")

        # ---------------------------------------------------------
        # Fixed Cryptographic Primitive and c-STE Times
        # ---------------------------------------------------------
        f.write("## Fixed BLS and c-STE Times\n\n")
        f.write(f"| Benchmark | Time ({UNIT_STR}) |\n")
        f.write("|---|------|\n")

        bls_group = results.get("bls time", {})
        bls_sign = bls_group.get("sign")
        bls_verify = bls_group.get("verify")
        decaggr = results.get("c-ste decaggr increment", {}).get(
            "9-way multi-pairing + subtraction"
        )
        encryption = results.get("c-ste encryption", {}).get("n=4096,t=2048")

        fixed_results = [
            ("BLS sign", bls_sign),
            ("BLS verify", bls_verify),
            ("c-STE DecAggr increment (9-way multi-pairing)", decaggr),
            ("c-STE Encryption (n=4096, t=2048)", encryption),
        ]
        for label, time_ms in fixed_results:
            time_str = f"{time_ms:.4f}" if time_ms is not None else "-"
            f.write(f"| {label} | {time_str} |\n")
        f.write("\n")

        # ---------------------------------------------------------
        # 3. Hints Table
        # ---------------------------------------------------------
        f.write("## Time to compute and verify the hint for a single party (Table 6)\n\n")
        f.write(f"| N | Naive approach ({UNIT_STR}) | c-STS ({UNIT_STR}) | Improvement | HintVerify ({UNIT_STR}) |\n")
        f.write("|---|-----------------|------------|----------------|-------------|\n")
        
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
            hint_verify = results.get("single hint verification time", {}).get(f"verify hint n = {n}")
            hint_verify_str = f"{hint_verify:.4f}" if hint_verify is not None else "-"
            
            if dyna is not None and c_sts is not None and c_sts != 0:
                improvement_str = f"{dyna / c_sts:.4f}"
            else:
                improvement_str = "-"
                
            f.write(f"| {n} | {dyna_str} | {c_sts_str} | {improvement_str} | {hint_verify_str} |\n")

        f.write("\n")

        # ---------------------------------------------------------
        # 4. Preprocess Table
        # ---------------------------------------------------------
        f.write("## Estimated preprocess time (Table 7)\n\n")
        f.write(f"| N | HintVerify ({UNIT_STR}) | N+1 G_1 additions ({UNIT_STR}) | T ({UNIT_STR}) | T x N ({UNIT_STR}) | C = T x N / 512 ({UNIT_STR}) |\n")
        f.write("|---|--------------|---------------|--------|------------------|----------------------------|\n")
        
        prep_group = results.get("preprocess estimate time", {})
        hint_verify_group = results.get("single hint verification time", {})
        prep_n_values = {
            n for test_id in prep_group
            if (n := extract_n(test_id)) is not None
        }
        hint_verify_n_values = {
            n for test_id in hint_verify_group
            if (n := extract_n(test_id)) is not None
        }

        for n in sorted(prep_n_values | hint_verify_n_values):
            hint_verify = hint_verify_group.get(f"verify hint n = {n}")
            add = prep_group.get(f"g1 add n+1 = {n}")

            hint_verify_str = f"{hint_verify:.4f}" if hint_verify is not None else "-"
            add_str = f"{add:.4f}" if add is not None else "-"

            if hint_verify is None or add is None:
                t_str = "-"
                t_times_n_str = "-"
                c_str = "-"
            else:
                t = hint_verify + add
                t_times_n = t * n
                c = t_times_n / 512
                t_str = f"{t:.4f}"
                t_times_n_str = f"{t_times_n:.4f}"
                c_str = f"{c:.4f}"

            f.write(f"| {n} | {hint_verify_str} | {add_str} | {t_str} | {t_times_n_str} | {c_str} |\n")

    print(f"Data extraction completed, results written to {output_file}")

if __name__ == "__main__":
    main()
