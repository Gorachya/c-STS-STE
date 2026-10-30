# README

This is the artifact of the paper "Practical Silent Threshold Signatures and Silent Threshold Encryption for Dynamic Committees" which has been accepted by ACM CCS 2026 (Cycle B, #1035).

## Repository Structure

*   `src/`: Contains the core implementation of the c-STS and c-STE cryptographic schemes.
*   `benches/`: Contains the benchmark scripts using the `criterion` framework (corresponding to Tables 1, 6, 7).
*   `examples/`: Contains the end-to-end integration examples (corresponding to Table 2).

## Prerequisites

### Hardware Baseline
The performance data reported in our paper was evaluated on a machine with an Intel Core Ultra 7 265K processor (3.90 GHz) and 64 GB of RAM, running Windows 11 with WSL2 and Ubuntu 20.04 LTS.
> Note: If you are evaluating this artifact on a machine with different specifications (e.g., a personal laptop), the *absolute* execution times will differ from the tables in the paper. However, the *relative trends* (e.g., aggregation time being independent of $N$) and the correctness of the algorithms will remain consistent, validating our main claims.

### Software Dependencies
This artifact requires **Rust** to build and run.
1. Install Rust (a recent stable version is sufficient) via `rustup`:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Python 3:** Required by the automation scripts (`run_benchmarks`) to parse the logs and generate the Markdown tables.

   - Please ensure Python 3 is installed and the `python` (or `python3`) executable is available in your system's `PATH`.
   - *(Note: Only Python standard libraries are used, no additional `pip` packages are required.)*

3. (If applicable for Linux) Install required build dependencies:

   ```bash
   sudo apt-get update
   sudo apt-get install build-essential pkg-config libssl-dev
   ```

## Important Notes on Execution Time (Please Read!)

Evaluating our protocols on large committee sizes (e.g., $N = 2^{20}$) is highly computationally intensive. 

*   **Long Preparation Time:** In the `preprocess` benchmark, generating $N$ Elliptic Curve points for $N=2^{20}$ can take **>20 minutes**.
*   **Long Initialization:** Similarly, the `endtoend` benchmark for signature aggregation requires substantial initialization time when $N \geq 2^{16}$.
*   Since the benchmarking framework `criterion` requires a minimum of 10 samples, we have set `group.sample_size(10)` for some long-running tests.

To accommodate different evaluation time constraints and ensure a smooth review process, **our automated evaluation scripts require a mandatory parameter (`fast` or `full`)** to control the testing scale.

## Automated Batch Evaluation

We provide scripts to automatically run the benchmarks and format the output. You **must** provide either `fast` or `full` as an argument; otherwise, the script will abort with an error.

### Option A: Fast Evaluation (Recommended for Functional Verification)
This mode limits the tests to a smaller range of parameters (smaller $N$) to quickly verify the correctness of the code, the execution flow, and the general performance trends.
*   **Expected Time:** ~10 minutes.
*   **Linux / macOS / Git Bash:** `sh run_benchmarks.sh fast`
*   **Windows (CMD):** `run_benchmarks.bat fast`

### Option B: Full Evaluation (Reproducing Paper Tables)
This mode runs the benchmarks over the complete range of parameters presented in the paper. 
*   **Expected Time:** Several hours (depending on your hardware).
*   **Linux / macOS / Git Bash:** `sh run_benchmarks.sh full`
*   **Windows (CMD):** `run_benchmarks.bat full`

### Output

Upon completion, the scripts will generate a file named `benchmark_results.md`. You can open this file to view the structured data tables corresponding to the experimental sections in our paper. 
*Note: If you ran the `fast` mode, the tables will show results up to a smaller $N$, but the relative performance trends will remain consistent with the paper.*

## Step-by-Step Evaluation (Reproducing Specific Tables)

You can manually execute specific benchmarks to reproduce individual tables. All benchmarks are executed using `cargo`.

*Note: Running these manual bench commands directly will execute the tests with their default (potentially maximum) parameters.*

### Table 1: Epoch Representation Computation

Measures the performance of the epoch representation computation.

```bash
cargo bench --bench epoch
```

### Table 6: Hints Computation

Measures the performance of hints computation.

```bash
cargo bench --bench hints
```

### Table 7: Preprocess

Measures the performance of preprocessing (used to estimate the parallel execution time).
*Note: This bench runs over various $N$ and may take a long time for the largest $N$.*

```bash
cargo bench --bench preprocess
```

The preprocessing numbers in Table 7 are cost-model estimates obtained from the component
microbenchmarks in `benches/preprocess.rs`. Assuming all hints are valid, HintVerify requires $N+1$
pairings and $N$ times the combined cost of $\mathsf{msm}_1(N)$ and $\mathsf{msm}_2(N)$; computing
$\mathsf{ak}$ and $\mathsf{vk}$ requires $N^2-1$ and $N$ $\mathbb{G}_1$ additions, respectively. The
average overhead per hint is therefore approximated by $T = 1$ pairing + $\mathsf{msm}_1(N)$ +
$\mathsf{msm}_2(N)$ + $N$ $\mathbb{G}_1$ additions.

Preprocessing is fully parallelizable across both participating parties and hardware threads. With node
parallelism $P_1=128$ and hardware parallelism $P_2=4$, the estimated execution time is
$C = T \times N / P$, where $P=P_1P_2=512$. Table 7 reports $T$, $T\times N$, and $C$ in milliseconds.
Table 7 is an estimate based on these component benchmarks, not an end-to-end preprocessing measurement.

### Table 2: End-to-End Performance (c-STS and c-STE)

You can run the end-to-end examples by specifying the operation (`sign` or `encrypt`), total size $N$, committee size $n$, and threshold $t$. The program will output the time taken for each step.

**Usage:**

```bash
cargo run --example endtoend --release -- <sign/encrypt> <N> <n> <t>
```

For demonstration efficiency, the end-to-end example uses the trapdoor shortcut implemented by `preprocess_trapdoor` instead of the regular hint-generation-and-preprocessing path. It also does not call HintVerify and therefore models the case in which all participants are honest. The regular path, which verifies hints and excludes invalid participants, is intentionally omitted from the end-to-end demo because generating hints and preprocessing all participants is too expensive for this purpose. Table 7's preprocessing estimates can be reproduced with `cargo bench --bench preprocess`; these are estimated component costs, not measurements of the trapdoor-based end-to-end preprocessing.

In `multi_evaluate`, the $O(n^2)$ implementation is used in the code. Benchmarking showed that this version is faster for the committee sizes in the paper's data range. Although its asymptotic complexity is worse than a divide-and-conquer implementation, the MSM operations dominate in the tested range, so it is the preferred implementation for these measurements.

*(Note: $N$ must be a power of 2. In our batch evaluation, we default to $t = n/2$.)*

**Examples:**

* To demonstrate **c-STE** performance under $N=8192$, $n=4096$, and $t=2048$:

  ```bash
  cargo run --example endtoend --release -- encrypt 8192 4096 2048
  ```

* To reproduce the **Aggregation time (Table 2)** for **c-STS** under $N=4096$, $n=2048$, and $t=1024$:

  ```bash
  cargo run --example endtoend --release -- sign 4096 2048 1024
  ```

  *Look for the "Aggregation" time in the console output to compare with Table 2.*

> As mathematically proven and demonstrated in the paper, the signature aggregation time is independent of $N$. Therefore, **we do not recommend running `endtoend` with excessively large $N$** due to the potentially long initialization time.
