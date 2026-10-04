from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class PhishTankReputationStatus(str, Enum):
    KNOWN_PHISHING = "KNOWN_PHISHING"
    NO_MATCH = "NO_MATCH"
    UNAVAILABLE = "UNAVAILABLE"


class PhishTankResult(BaseModel):
    status: PhishTankReputationStatus = Field(
        ...,
        description="Reputation status: KNOWN_PHISHING, NO_MATCH, or UNAVAILABLE",
    )
    in_database: Optional[bool] = Field(
        None, description="Whether URL exists in PhishTank database"
    )
    is_valid_phish: Optional[bool] = Field(
        None, description="Whether actively confirmed as a valid phish"
    )
    verified: Optional[bool] = Field(
        None, description="Whether community verified"
    )
    phish_id: Optional[int] = Field(
        None, description="PhishTank submission identifier if found"
    )
    phish_detail_url: Optional[str] = Field(
        None, description="PhishTank incident detail page URL"
    )
    message: str = Field(
        ..., description="Human-readable description of reputation findings"
    )
    caution_note: str = Field(
        ...,
        description="Security clarification explicitly stating that 'not found' does not equal safe",
    )


class UrlSignal(BaseModel):
    url: str = Field(..., description="The full extracted URL")
    scheme: str = Field(..., description="Protocol scheme: http or https")
    is_https: bool = Field(..., description="True if using encrypted HTTPS")
    domain: str = Field(..., description="Extracted hostname/domain")
    is_suspicious: bool = Field(
        default=False,
        description="True if local heuristics flag suspicious signals",
    )
    suspicious_signals: List[str] = Field(
        default_factory=list,
        description="List of detected local security signals and indicators",
    )
    reputation: Optional[PhishTankResult] = Field(
        default=None,
        description="PhishTank reputation lookup evidence",
    )
    is_shortened: bool = Field(
        default=False,
        description="True if URL uses a known link-shortening service",
    )
    resolved_url: Optional[str] = Field(
        default=None,
        description="Safely expanded destination URL if shortener was unmasked",
    )
    is_obfuscated: bool = Field(
        default=False,
        description="True if URL uses obfuscated IP, hex/dword/octal encoding, or deceptive host encoding",
    )
    zero_day_indicators: List[str] = Field(
        default_factory=list,
        description="Specific zero-day structural evasion indicators detected locally",
    )


STANDARD_SCAM_CATEGORIES = [
    "UPI Payment Fraud",
    "Bank/Financial Impersonation",
    "Credential Phishing",
    "Delivery Smishing",
    "Fake Job Offer",
    "Lottery/Prize Fraud",
    "Government/Identity Impersonation",
    "Friend/Family Impersonation",
    "Tech Support Scam",
    "Investment/Crypto Scam",
    "Routine / Legitimate Communication",
]

CONTROLLED_ATTACK_TYPES = [
    "Bank Impersonation",
    "Credential Phishing",
    "UPI/Payment Fraud",
    "OTP Theft",
    "Password/Account Credential Theft",
    "Malicious Download",
    "Malicious Link",
    "Typosquatting",
    "Punycode/IDN Homograph",
    "URL Obfuscation",
    "Open Redirect Abuse",
    "Suspicious Shortened URL",
    "Brand Impersonation",
    "Government Impersonation",
    "Delivery Scam",
    "Fake Job Scam",
    "Lottery/Prize Scam",
    "Investment/Crypto Scam",
    "Tech Support Scam",
    "Friend/Family Impersonation",
    "Social Engineering",
    "Urgency/Threat Manipulation",
    "Trust/Grooming Manipulation",
]


class EvidenceSummary(BaseModel):
    gemini_assessment: str = Field(
        ...,
        description="Summary of Gemini AI analysis findings",
    )
    local_url_findings: str = Field(
        ...,
        description="Summary of local URL security heuristics",
    )
    phishtank_findings: str = Field(
        ...,
        description="Summary of PhishTank threat intelligence findings",
    )
    fusion_rationale: str = Field(
        ...,
        description="Transparent rationale explaining how multi-source evidence determined the final risk assessment",
    )
    heuristic_confidence: Optional[str] = Field(
        default=None,
        description="Internal heuristic indicator (e.g., HIGH, MEDIUM, CAUTIONARY) based on corroborating evidence, not a calibrated statistical probability",
    )


class AnalysisRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=3,
        max_length=5000,
        description="The suspicious message content to be analyzed",
    )


class ConversationMessage(BaseModel):
    sender: Optional[str] = Field(
        default="Unknown",
        description="Sender handle, name, or role (e.g., 'Unknown', 'Caller', 'You')",
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Content of the individual message in sequential order",
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="Optional timestamp or sequence label (e.g., '10:05 AM', 'Day 2')",
    )


class ConversationAnalysisRequest(BaseModel):
    messages: List[ConversationMessage] = Field(
        ...,
        min_length=2,
        max_length=25,
        description="Chronological sequence of conversation turns to analyze for cumulative grooming and scam tactics",
    )


class ConversationTactics(BaseModel):
    trust_building_observed: bool = Field(
        default=False,
        description="Whether rapport-building, flattery, or false familiarity was detected early in the thread",
    )
    urgency_escalation_observed: bool = Field(
        default=False,
        description="Whether pressure, threats, or artificial deadlines escalated over time",
    )
    payment_or_credential_demanded: bool = Field(
        default=False,
        description="Whether money, gift cards, wire transfers, crypto, OTPs, or passwords were asked",
    )
    grooming_pattern: Optional[str] = Field(
        default=None,
        description="Identified multi-turn social engineering progression or manipulation strategy",
    )


class AnalysisResponse(BaseModel):
    risk_level: RiskLevel = Field(
        ..., description="Risk assessment level: LOW, MEDIUM, or HIGH"
    )
    scam_category: str = Field(
        ..., description="Detected category of scam or legitimate communication type"
    )
    suspicious_indicators: List[str] = Field(
        default_factory=list,
        description="Key indicators or red flags found in the message",
    )
    explanation: str = Field(
        ...,
        description="Clear explanation explaining the rationale behind the risk score and indicators",
    )
    recommended_action: str = Field(
        ...,
        description="Recommended safe action or precautions the user should take immediately",
    )
    urls_detected: List[UrlSignal] = Field(
        default_factory=list,
        description="Extracted URLs with local security analysis signals and PhishTank reputation",
    )
    evidence_summary: Optional[EvidenceSummary] = Field(
        default=None,
        description="Transparent multi-source evidence summary and fusion rationale",
    )
    conversation_tactics: Optional[ConversationTactics] = Field(
        default=None,
        description="Cumulative multi-turn tactics breakdown if analyzing a multi-message thread",
    )
    attack_types: List[str] = Field(
        default_factory=list,
        description="All distinct attack techniques detected in the analyzed content, not just the primary scam category",
    )
