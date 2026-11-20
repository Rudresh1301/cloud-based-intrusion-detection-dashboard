"""
Top-level forwarder for detector module to ensure backward compatibility.
"""
from core.detector import IntrusionDetector, analyze_logs

__all__ = ["IntrusionDetector", "analyze_logs"]
