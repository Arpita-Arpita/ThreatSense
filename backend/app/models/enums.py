"""Python enums mirroring the PostgreSQL ENUM types in schema.sql (rev2)."""
import enum


class AdminRole(str, enum.Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    VIEWER = "VIEWER"


class AuditAction(str, enum.Enum):
    LOGIN = "LOGIN"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    ACKNOWLEDGE = "ACKNOWLEDGE"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
    EXPORT = "EXPORT"


class TransportType(str, enum.Enum):
    TLS = "TLS"
    TCP = "TCP"
    UDP = "UDP"


class SourceType(str, enum.Enum):
    PCAP = "PCAP"
    SYSLOG = "SYSLOG"


class SourceStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ERROR = "ERROR"


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(str, enum.Enum):
    PORT_SCAN = "PORT_SCAN"
    DDOS = "DDOS"
    C2 = "C2"
    BRUTE_FORCE = "BRUTE_FORCE"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class AlertChannel(str, enum.Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    IN_APP = "IN_APP"


class AlertStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"


class AlertSeverityThreshold(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    ALL = "ALL"
