/**
 * Module 2 Regex Rule Catalogue (Section 6.2)
 * Categorized into: Identifiers, Secrets (Hard Rules), Code & Infra, Company-Specific.
 */

const REGEX_RULES = [
  // ==========================================
  // 1. IDENTIFIERS
  // ==========================================
  {
    id: "ID-01",
    category: "Aadhaar",
    description: "12-digit Indian Aadhaar number with Verhoeff checksum",
    pattern: /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/g,
    weight: 0.8,
    hard: false,
    validator: (match) => typeof Verhoeff !== 'undefined' ? Verhoeff.validate(match) : true
  },
  {
    id: "ID-02",
    category: "PAN",
    description: "Indian PAN Card format (5 letters, 4 digits, 1 letter)",
    pattern: /\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b/g,
    weight: 0.7,
    hard: false
  },
  {
    id: "ID-03",
    category: "US-SSN",
    description: "US Social Security Number format (3-2-4 digits)",
    pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    weight: 0.8,
    hard: false
  },
  {
    id: "ID-04",
    category: "PaymentCard",
    description: "Payment card numbers (13-19 digits) with Luhn validation",
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    weight: 0.9,
    hard: false,
    validator: (match) => typeof Luhn !== 'undefined' ? Luhn.validate(match) : true
  },
  {
    id: "ID-05",
    category: "Email",
    description: "Email addresses (count-based weight scaling)",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    weight: 0.1, // Scales up to 0.5 if 5 or more emails appear
    hard: false,
    countScaled: true
  },
  {
    id: "ID-06",
    category: "Phone",
    description: "Indian mobile phone numbers (10 digits starting 6-9, optional +91)",
    pattern: /(?:\+91[-\s]?)?[6-9]\d{9}\b/g,
    weight: 0.1,
    hard: false,
    countScaled: true
  },
  {
    id: "ID-07",
    category: "BankAccount",
    description: "IFSC-like codes and bank account keywords",
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    weight: 0.6,
    hard: false
  },

  // ==========================================
  // 2. SECRETS (Hard rules force floor >= 0.9)
  // ==========================================
  {
    id: "SE-01",
    category: "PrivateKey",
    description: "Private key header lines",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    weight: 1.0,
    hard: true
  },
  {
    id: "SE-02",
    category: "CloudAccessKey",
    description: "AWS-style access key ID (e.g. AKIA...)",
    pattern: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    weight: 1.0,
    hard: true
  },
  {
    id: "SE-03",
    category: "HighEntropySecret",
    description: "Long high-entropy tokens next to secret keywords",
    pattern: /(?:api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["']?([A-Za-z0-9_\-]{24,})["']?/gi,
    weight: 0.8,
    hard: false
  },
  {
    id: "SE-04",
    category: "PasswordAssignment",
    description: "Password assignments in code or configs",
    pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi,
    weight: 0.9,
    hard: false
  },
  {
    id: "SE-05",
    category: "ConnectionString",
    description: "Database connection strings containing credentials",
    pattern: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:[^@\s]+@[a-zA-Z0-9_.-]+/gi,
    weight: 1.0,
    hard: true
  },
  {
    id: "SE-06",
    category: "JWT",
    description: "JSON Web Token (JWT) three-part format",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    weight: 0.8,
    hard: false
  },
  {
    id: "SE-07",
    category: "BearerToken",
    description: "Authorization Bearer header lines",
    pattern: /\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b/gi,
    weight: 0.7,
    hard: false
  },

  // ==========================================
  // 3. CODE AND INFRASTRUCTURE
  // ==========================================
  {
    id: "CO-01",
    category: "CodeBlock",
    description: "Dense code blocks (high frequency of braces, keywords)",
    customCheck: (text) => {
      const lines = text.split("\n");
      if (lines.length < 30) return false;
      const codeMatches = (text.match(/[{};=><()[\]]|function|class|return|import|export|const|let|var|def\s/g) || []).length;
      return (codeMatches / text.length) > 0.05;
    },
    weight: 0.4,
    hard: false
  },
  {
    id: "CO-02",
    category: "PrivateIP",
    description: "Private RFC 1918 IP addresses",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    weight: 0.5,
    hard: false
  },
  {
    id: "CO-03",
    category: "InternalRepo",
    description: "Internal Git repository URLs or paths",
    pattern: /\b(?:git@|https?:\/\/)(?:gitlab|github|bitbucket)\.[a-zA-Z0-9.-]+\/(?:internal|corp|enterprise)\/[a-zA-Z0-9_.-]+/gi,
    weight: 0.5,
    hard: false
  },
  {
    id: "CO-04",
    category: "InternalSQL",
    description: "SQL statements referencing database tables",
    pattern: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?[a-zA-Z0-9_]+[`"']?\s+(?:WHERE|SET|VALUES)/gi,
    weight: 0.5,
    hard: false
  },

  // ==========================================
  // 4. COMPANY SPECIFIC
  // ==========================================
  {
    id: "CM-01",
    category: "ConfidentialityMarker",
    description: "Corporate confidentiality warning phrases",
    pattern: /\b(?:confidential|internal\s+only|do\s+not\s+distribute|proprietary|strictly\s+private|not\s+for\s+external)\b/gi,
    weight: 0.7,
    hard: false
  },
  {
    id: "CM-02",
    category: "ProjectCodename",
    description: "Configured corporate secret project names",
    pattern: /\b(?:Project\s+(?:Titan|Apollo|Manhattan|Blackbird|Vanguard|Phoenix))\b/gi,
    weight: 0.6,
    hard: false
  },
  {
    id: "CM-03",
    category: "InternalEmployeeID",
    description: "CERT-style employee IDs (3 letters + 4 digits, 3 or more distinct occurrences)",
    customCheck: (text) => {
      const matches = text.match(/\b[A-Z]{3}\d{4}\b/g) || [];
      const distinct = new Set(matches);
      return distinct.size >= 3;
    },
    weight: 0.5,
    hard: false
  },
  {
    id: "CM-04",
    category: "BulkTabularData",
    description: "20 or more lines with consistent delimiter count (>= 4 columns)",
    customCheck: (text) => {
      const lines = text.split("\n").filter(l => l.trim().length > 0);
      if (lines.length < 20) return false;
      const commaCounts = lines.map(l => (l.match(/,/g) || []).length);
      const pipeCounts = lines.map(l => (l.match(/\|/g) || []).length);
      const tabCounts = lines.map(l => (l.match(/\t/g) || []).length);
      
      const checkDelim = (counts) => {
        const modeCount = counts[0];
        if (modeCount < 3) return false; // >= 4 columns requires >= 3 delimiters
        const matchShare = counts.filter(c => c === modeCount).length / counts.length;
        return matchShare > 0.8;
      };
      return checkDelim(commaCounts) || checkDelim(pipeCounts) || checkDelim(tabCounts);
    },
    weight: 0.6,
    hard: false
  }
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { REGEX_RULES };
}
