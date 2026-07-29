from __future__ import annotations

from .beacon import detect_beacons, score_channel
from .models import BeaconFinding, ChannelKey, Connection, DetectionConfig, Technique
from .zeek_loader import iter_conn_log, load_conn_log

__version__ = "0.1.0"

__all__ = [
    "BeaconFinding",
    "ChannelKey",
    "Connection",
    "DetectionConfig",
    "Technique",
    "detect_beacons",
    "iter_conn_log",
    "load_conn_log",
    "score_channel",
    "__version__",
]
