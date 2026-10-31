"""
Module 3 Regex Rule Catalogue (Section 9 C4 & Port of Module 2 rules.js)
Categorized into: Identifiers, Secrets (Hard Rules), Code & Infra, Company-Specific.
Uses third-party 'regex' library with timeout parameter to prevent regex DoS freezes (Section 2 #13).
"""

from typing import List, Dict, Any, Callable, Optional
import regex
from .checksums import Verhoeff, Luhn

REGEX_TIMEOUT_SEC = 1.0

class RegexRule:
    def __init__(
        self,
        rule_id: str,
        category: str,
        description: str,
        pattern_str: Optional[str] = None,
        flags: int = 0,
        weight: float = 0.5,
        hard: bool = False,
        count_scaled: bool = False,
        validator: Optional[Callable[[str], bool]] = None,
        custom_check: Optional[Callable[[str], bool]] = None
    ):
        self.id = rule_id
        self.category = category
        self.description = description
        self.pattern = regex.compile(pattern_str, flags) if pattern_str else None
        self.weight = weight
        self.hard = hard
        self.count_scaled = count_scaled
        self.validator = validator
        self.custom_check = custom_check

def check_code_block(text: str) -> bool:
    lines = text.split("\n")
    if len(lines) < 30:
        return False
    symbols = regex.findall(r"[{}\;=><()\[\]]|function|class|return|import|export|const|let|var|def\s", text, timeout=REGEX_TIMEOUT_SEC)
    return (len(symbols) / max(len(text), 1)) > 0.05

def check_internal_employee_id(text: str) -> bool:
    matches = regex.findall(r"\b[A-Z]{3}\d{4}\b", text, timeout=REGEX_TIMEOUT_SEC)
    distinct = set(matches)
    return len(distinct) >= 3

def check_bulk_tabular_data(text: str) -> bool:
    lines = [l for l in text.split("\n") if l.strip()]
    if len(lines) < 20:
        return False
    comma_counts = [l.count(",") for l in lines]
    pipe_counts = [l.count("|") for l in lines]
    tab_counts = [l.count("\t") for l in lines]

    def check_delim(counts):
        if not counts:
            return False
        mode_count = counts[0]
        if mode_count < 3:
            return False
        match_share = sum(1 for c in counts if c == mode_count) / len(counts)
        return match_share > 0.8

    return check_delim(comma_counts) or check_delim(pipe_counts) or check_delim(tab_counts)


REGEX_RULES: List[RegexRule] = [
    # 1. IDENTIFIERS
    RegexRule(
        rule_id="ID-01",
        category="Aadhaar",
        description="12-digit Indian Aadhaar number with Verhoeff checksum",
        pattern_str=r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        weight=0.8,
        validator=Verhoeff.validate
    ),
    RegexRule(
        rule_id="ID-02",
        category="PAN",
        description="Indian PAN Card format (5 letters, 4 digits, 1 letter)",
        pattern_str=r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b",
        weight=0.7
    ),
    RegexRule(
        rule_id="ID-03",
        category="US-SSN",
        description="US Social Security Number format (3-2-4 digits)",
        pattern_str=r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        weight=0.8
    ),
    RegexRule(
        rule_id="ID-04",
        category="PaymentCard",
        description="Payment card numbers (13-19 digits) with Luhn validation",
        pattern_str=r"\b(?:\d[ -]*?){13,19}\b",
        weight=0.9,
        validator=Luhn.validate
    ),
    RegexRule(
        rule_id="ID-05",
        category="Email",
        description="Email addresses (count-based weight scaling)",
        pattern_str=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        weight=0.1,
        count_scaled=True
    ),
    RegexRule(
        rule_id="ID-06",
        category="Phone",
        description="Indian mobile phone numbers (10 digits starting 6-9, optional +91)",
        pattern_str=r"(?:\+91[-\s]?)?[6-9]\d{9}\b",
        weight=0.1,
        count_scaled=True
    ),
    RegexRule(
        rule_id="ID-07",
        category="BankAccount",
        description="IFSC-like codes and bank account keywords",
        pattern_str=r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
        weight=0.6
    ),

    # 2. SECRETS (Hard rules force floor >= 0.9)
    RegexRule(
        rule_id="SE-01",
        category="PrivateKey",
        description="Private key header lines",
        pattern_str=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        weight=1.0,
        hard=True
    ),
    RegexRule(
        rule_id="SE-02",
        category="CloudAccessKey",
        description="AWS-style access key ID (e.g. AKIA...)",
        pattern_str=r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        weight=1.0,
        hard=True
    ),
    RegexRule(
        rule_id="SE-03",
        category="HighEntropySecret",
        description="Long high-entropy tokens next to secret keywords",
        pattern_str=r"""(?:api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["']?([A-Za-z0-9_\-]{24,})["']?""",
        flags=regex.IGNORECASE,
        weight=0.8
    ),
    RegexRule(
        rule_id="SE-04",
        category="PasswordAssignment",
        description="Password assignments in code or configs",
        pattern_str=r"""\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?""",
        flags=regex.IGNORECASE,
        weight=0.9
    ),
    RegexRule(
        rule_id="SE-05",
        category="ConnectionString",
        description="Database connection strings containing credentials",
        pattern_str=r"\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+",
        flags=regex.IGNORECASE,
        weight=1.0,
        hard=True
    ),
    RegexRule(
        rule_id="SE-06",
        category="JWT",
        description="JSON Web Token (JWT) three-part format",
        pattern_str=r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        weight=0.8
    ),
    RegexRule(
        rule_id="SE-07",
        category="BearerToken",
        description="Authorization Bearer header lines",
        pattern_str=r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b",
        flags=regex.IGNORECASE,
        weight=0.7
    ),

    # 3. CODE AND INFRASTRUCTURE
    RegexRule(
        rule_id="CO-01",
        category="CodeBlock",
        description="Dense code blocks (high frequency of braces, keywords)",
        custom_check=check_code_block,
        weight=0.4
    ),
    RegexRule(
        rule_id="CO-02",
        category="PrivateIP",
        description="Private RFC 1918 IP addresses",
        pattern_str=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        weight=0.5
    ),
    RegexRule(
        rule_id="CO-03",
        category="InternalRepo",
        description="Internal Git repository URLs or paths",
        pattern_str=r"\b(?:git@|https?:\/\/)(?:gitlab|github|bitbucket)\.[a-zA-Z0-9.-]+\/(?:internal|corp|enterprise)\/[a-zA-Z0-9_.-]+",
        flags=regex.IGNORECASE,
        weight=0.5
    ),
    RegexRule(
        rule_id="CO-04",
        category="InternalSQL",
        description="SQL statements referencing database tables",
        pattern_str=r"\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`\"']?[a-zA-Z0-9_]+[`\"']?\s+(?:WHERE|SET|VALUES)",
        flags=regex.IGNORECASE,
        weight=0.5
    ),

    # 4. COMPANY SPECIFIC
    RegexRule(
        rule_id="CM-01",
        category="ConfidentialityMarker",
        description="Corporate confidentiality warning phrases",
        pattern_str=r"\b(?:confidential|internal\s+only|do\s+not\s+distribute|proprietary|strictly\s+private|not\s+for\s+external)\b",
        flags=regex.IGNORECASE,
        weight=0.7
    ),
    RegexRule(
        rule_id="CM-02",
        category="ProjectCodename",
        description="Configured corporate secret project names",
        pattern_str=r"\b(?:Project\s+(?:Titan|Apollo|Manhattan|Blackbird|Vanguard|Phoenix))\b",
        flags=regex.IGNORECASE,
        weight=0.6
    ),
    RegexRule(
        rule_id="CM-03",
        category="InternalEmployeeID",
        description="CERT-style employee IDs (3 letters + 4 digits, 3 or more distinct occurrences)",
        custom_check=check_internal_employee_id,
        weight=0.5
    ),
    RegexRule(
        rule_id="CM-04",
        category="BulkTabularData",
        description="20 or more lines with consistent delimiter count (>= 4 columns)",
        custom_check=check_bulk_tabular_data,
        weight=0.6
    )
]
