"""Shared helpers: refuse to start if another process already uses lots of GPU memory."""
import subprocess, sys, torch

def gpu_free_or_exit(min_free_gb: float):
    free, total = torch.cuda.mem_get_info()
    free_gb, total_gb = free / 2**30, total / 2**30
    print(f"[gpu] free {free_gb:.1f} / {total_gb:.1f} GiB")
    if free_gb < min_free_gb:
        print(subprocess.run(["nvidia-smi"], capture_output=True, text=True).stdout)
        print(f"[gpu] SKIP: need >= {min_free_gb} GiB free (someone else is using the GPU)")
        sys.exit(3)

def report(tag: str):
    alloc = torch.cuda.max_memory_allocated() / 2**30
    resv = torch.cuda.max_memory_reserved() / 2**30
    print(f"[vram] {tag}: peak allocated {alloc:.2f} GiB, peak reserved {resv:.2f} GiB")
