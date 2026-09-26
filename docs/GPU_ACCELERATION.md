# Optional GPU audit hashing

The GPU helper and benchmark recompute SHA-256 hashes for canonical audit
record bodies in parallel. The feature is optional and is not connected to
`GovernanceKernel.verify_audit()`. CPU verification remains authoritative:
the kernel checks audit records on its normal CPU path, and the standalone
helper checks previous-hash and delta-root linkage on the CPU. Permit, policy,
authority, replay, and durable-state decisions stay CPU-only. The benchmark
requires exact CPU/GPU digest equality before reporting timing results.

## Implementations and backends

The benchmark defaults to a fused Triton implementation. Use
`--implementation torch` for the eager PyTorch implementation. Both CUDA and
ROCm PyTorch builds use the `torch.cuda` tensor API; the helper detects ROCm
through `torch.version.hip`. Use `--device auto`, `--device cuda`, or
`--device rocm` to select or require the backend.

Install the optional dependency in an environment with a compatible CUDA or
ROCm PyTorch build and its required driver/runtime. The extra declares PyTorch and NumPy; it does not install a GPU driver or choose
the correct vendor-specific PyTorch wheel:

```bash
python -m pip install -e ".[gpu]"
python -c "import torch; print(torch.__version__, torch.version.hip, torch.cuda.is_available())"
```

Continue when the availability check confirms the intended accelerator. Follow
the official installation instructions for the matching PyTorch and vendor
runtime versions.

## Run the benchmark

```bash
python scripts/benchmark_gpu.py --device auto --implementation triton --sizes 1000,10000,100000
```

The benchmark checks every GPU digest against the CPU reference before timing.
It reports end-to-end CPU and GPU latency. For the Triton path it also reports
canonicalization, host preparation, host-to-device transfer, kernel, device-
to-host copy, and digest-formatting stages. Results are written as JSON and
CSV; timestamped output names are used by default, and existing files are
protected unless `--overwrite` is specified. Use `--help` to see output-path
options.

Install the optional test tools and run the correctness tests in the same
CUDA/ROCm environment:

```bash
python -m pip install -e ".[gpu,test]"
python -m pytest tests/test_gpu_acceleration.py -q
```

GPU-specific cases skip when no compatible GPU runtime is available. CPU
reference and serialization checks still run. The repository's normal kernel
verification remains CPU-only regardless of whether GPU support is installed.

## Upstream benchmark evidence

The upstream [Pulpo PR #267](https://github.com/Ironnember/Pulpo1.0/pull/267)
reports user-run validation on an AMD Radeon RX 7900 XT using ROCm 7.2.1 and
PyTorch 2.9.1. The reported end-to-end GPU times were near CPU parity at larger
batches; the PR does not claim a speedup. It attributes much of the remaining
cost to canonical JSON serialization and host-side preparation/result
formatting. These are measurements from the upstream Pulpo project, not a
performance claim for every Pulpo Autonomous deployment or accelerator.
