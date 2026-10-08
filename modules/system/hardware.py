import os
import shutil
import subprocess
from typing import Any, Dict

import psutil


def get_gpu_vram() -> Dict[str, Any]:
    """Query NVIDIA GPU stats (VRAM used/total, GPU temp, name) via nvidia-smi."""
    try:
        cmd = [
            "nvidia-smi",
            "--query-gpu=name,memory.total,memory.used,memory.free,temperature.gpu,utilization.gpu",
            "--format=csv,noheader,nounits",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=5)
        lines = res.stdout.strip().splitlines()
        gpus = []
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 6:
                gpus.append({
                    "name": parts[0],
                    "memory_total_mb": float(parts[1]),
                    "memory_used_mb": float(parts[2]),
                    "memory_free_mb": float(parts[3]),
                    "temperature_c": float(parts[4]),
                    "utilization_percent": float(parts[5]),
                })
        return {"available": True, "gpus": gpus}
    except Exception as e:
        return {"available": False, "error": f"nvidia-smi unavailable: {e}"}


def get_system_health() -> Dict[str, Any]:
    """Get complete snapshot of CPU, RAM, Disk (C, D, F), and GPU VRAM."""
    # RAM
    vmem = psutil.virtual_memory()
    ram_stats = {
        "total_gb": round(vmem.total / (1024**3), 2),
        "used_gb": round(vmem.used / (1024**3), 2),
        "available_gb": round(vmem.available / (1024**3), 2),
        "percent": vmem.percent,
    }

    # Disks
    disks = {}
    for drive in ["C:\\", "D:\\", "F:\\"]:
        if os.path.exists(drive):
            try:
                usage = shutil.disk_usage(drive)
                disks[drive] = {
                    "total_gb": round(usage.total / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "used_percent": round((usage.used / usage.total) * 100, 1),
                }
            except Exception:
                pass

    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.2)

    # GPU
    gpu_stats = get_gpu_vram()

    return {
        "cpu_usage_percent": cpu_percent,
        "ram": ram_stats,
        "disks": disks,
        "gpu": gpu_stats,
    }
