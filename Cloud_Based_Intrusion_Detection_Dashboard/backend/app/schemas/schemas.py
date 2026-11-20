from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# Authentication
class UserRegister(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = "SOC Analyst"
    role: Optional[str] = "Security Analyst"

class UserLogin(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    uid: str
    email: str
    full_name: str
    role: str
    auth_provider: str = "Firebase / Local BaaS"

class AuthResponse(BaseModel):
    token: str
    user: UserProfile
    message: str

# Security Log Records
class LogEntry(BaseModel):
    id: Optional[str] = None
    timestamp: str
    source_ip: str
    username: str
    event_type: str
    status: str
    endpoint: str
    classification: Optional[str] = "Normal"
    risk_score: Optional[int] = 0

class LogValidationResult(BaseModel):
    valid: bool
    errors: List[str]
    warnings: List[str]
    stats: Dict[str, Any]
    preview: List[Dict[str, Any]]

# Alerts
class AlertEntry(BaseModel):
    id: str
    timestamp: str
    source_ip: str
    username: Optional[str] = "unknown"
    alert_type: str
    severity: str  # Critical, High, Medium, Low
    status: str = "New"  # New, Investigating, Resolved
    description: Optional[str] = ""
    evidence: Optional[str] = ""
    recommended_action: Optional[str] = ""
    detection_method: str = "rule-based"  # rule-based, isolation-forest-ml, behavioral
    risk_score: int = 50

class AlertStatusUpdate(BaseModel):
    status: str  # New, Investigating, Resolved

# IP Intelligence
class IPIntelligenceItem(BaseModel):
    ip_address: str
    total_events: int
    suspicious_events: int
    attack_categories: List[str]
    risk_score: int
    first_observed: str
    last_observed: str
    threat_status: str  # Critical, High, Medium, Low, Clean
    country: Optional[str] = "Local/Private"
    country_code: Optional[str] = "LOC"
    city: Optional[str] = "Internal Network"
    isp: Optional[str] = "Enterprise Gateway"
    latitude: Optional[float] = None
    longitude: Optional[float] = None

# Analytics & Dashboard
class MetricCard(BaseModel):
    title: str
    value: Any
    trend: str
    color: str
    icon: str

class TimelinePoint(BaseModel):
    time: str
    normal_traffic: int
    threats: int

class DonutSlice(BaseModel):
    name: str
    count: int
    percentage: float
    color: str

class RiskIndicator(BaseModel):
    level: str  # CRITICAL RISK, HIGH RISK, MEDIUM RISK, LOW RISK
    percentage: int
    color: str
    description: str
    contributing_factors: List[str]

class DashboardOverview(BaseModel):
    total_requests: int
    threats_detected: int
    suspicious_ips: int
    blocked_attempts: int
    trend_requests: str
    trend_threats: str
    trend_ips: str
    trend_blocked: str
    risk_indicator: RiskIndicator
    activity_timeline: List[TimelinePoint]
    attack_distribution: List[DonutSlice]
    top_attacking_ips: List[Dict[str, Any]]
    recent_alerts: List[AlertEntry]
    last_analysis_time: str
    system_status: str = "Online"

# Cloud Services Health
class ServiceHealth(BaseModel):
    name: str
    status: str  # connected, degraded, disconnected, fallback
    latency_ms: Optional[float] = None
    details: str
    provider: str

class CloudStatusResponse(BaseModel):
    all_healthy: bool
    active_database: str
    active_storage: str
    services: List[ServiceHealth]

# Settings
class SystemSettings(BaseModel):
    brute_force_threshold: int = 5
    brute_force_critical: int = 10
    high_volume_threshold: int = 50
    ml_contamination: float = 0.1
    time_window_minutes: int = 10
    auto_refresh_seconds: int = 15
    database_mode: str = "sqlite"

# Reports
class ReportGenerationRequest(BaseModel):
    title: Optional[str] = "SOC Security Audit & Threat Intelligence Report"
    include_raw_logs: Optional[bool] = False
    notes: Optional[str] = ""

class ReportSummary(BaseModel):
    id: str
    filename: str
    generated_at: str
    total_events: int
    threats_found: int
    risk_level: str
    download_url: str
    storage_type: str
