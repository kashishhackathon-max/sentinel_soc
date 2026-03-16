"""
Sentinel System Metrics
Tracks incident volume, severity distribution, and SOC performance.
"""
from datetime import datetime
import json

METRICS_FILE = "app/metrics/metrics_db.json"

def init_metrics():
    try:
        with open(METRICS_FILE, "r") as f:
            return json.load(f)
    except:
        return {
            "total_incidents": 0,
            "critical_threats": 0,
            "attestations_success": 0,
            "remediations_triggered": 0,
            "recommendations_generated": 0,
            "avg_latency_ms": 1200,
            "last_updated": datetime.now().isoformat()
        }

def update_metric(key: str, increment: int = 1):
    metrics = init_metrics()
    if key in metrics:
        metrics[key] += increment
    metrics["last_updated"] = datetime.now().isoformat()
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f)

def get_metrics():
    return init_metrics()

def save_monitoring_active(active: bool):
    metrics = init_metrics()
    metrics["monitoring_active"] = active
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f)

def get_monitoring_active() -> bool:
    metrics = init_metrics()
    return metrics.get("monitoring_active", False)
