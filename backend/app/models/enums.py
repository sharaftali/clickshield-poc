import enum


class ProtectionMode(str, enum.Enum):
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class UserRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class CampaignType(str, enum.Enum):
    SEARCH = "SEARCH"
    PERFORMANCE_MAX = "PERFORMANCE_MAX"
    DISPLAY = "DISPLAY"
    VIDEO = "VIDEO"
    SHOPPING = "SHOPPING"


class CampaignStatus(str, enum.Enum):
    ENABLED = "ENABLED"
    PAUSED = "PAUSED"
    REMOVED = "REMOVED"


class Verdict(str, enum.Enum):
    SAFE = "SAFE"
    MONITOR = "MONITOR"
    FLAG = "FLAG"
    FRAUD = "FRAUD"


class ClientVerdict(str, enum.Enum):
    LEGITIMATE = "legitimate"
    FRAUD = "fraud"


class EventType(str, enum.Enum):
    AD_LANDING = "ad_landing"
    PAGE_VIEW = "page_view"
    SCROLL = "scroll"
    CLICK = "click"
    FORM_START = "form_start"
    FORM_SUBMIT = "form_submit"
    PHONE_CLICK = "phone_click"
    OUTBOUND_CLICK = "outbound_click"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    CONVERSION = "conversion"


class ExclusionStatus(str, enum.Enum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"
    REMOVED = "REMOVED"
    SKIPPED = "SKIPPED"


class Platform(str, enum.Enum):
    GOOGLE = "GOOGLE"
    META = "META"
    MICROSOFT = "MICROSOFT"
    TIKTOK = "TIKTOK"


class ActionType(str, enum.Enum):
    ADD_IP_EXCLUSION = "ADD_IP_EXCLUSION"
    REMOVE_IP_EXCLUSION = "REMOVE_IP_EXCLUSION"
    ADD_AUDIENCE_EXCLUSION = "ADD_AUDIENCE_EXCLUSION"


class ActionStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


class AuditResult(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"
