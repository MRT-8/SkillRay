"""SR-SUPPLY-xxx: Supply chain attack rules."""

from ..models import Rule, Severity, ThreatCategory, TargetType
from .registry import register

# SR-SUPPLY-001: postinstall script executing arbitrary code
register(Rule(
    rule_id="SR-SUPPLY-001",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.HIGH,
    title="Post-install script executes arbitrary code",
    description="Package postinstall/setup scripts running shell commands or downloading code.",
    recommendation="Review postinstall scripts for unexpected code execution.",
    targets=(TargetType.SCRIPT, TargetType.CONFIG),
    engine="regex",
), patterns=[
    r'"postinstall"\s*:\s*"[^"]*(?:sh |bash |node |python)',
    r"setup\s*\(\s*[^)]*cmdclass",
    r"(?:postinstall|preinstall|install)\s*[=:]\s*['\"].*(?:curl|wget|sh\b|bash\b|python)",
])

# SR-SUPPLY-002: Known malicious / typosquatting packages
register(Rule(
    rule_id="SR-SUPPLY-002",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.HIGH,
    title="Possible typosquatting or malicious package dependency",
    description="Package name matches known typosquatting patterns.",
    recommendation="Verify package names carefully against the official registry.",
    targets=(TargetType.CONFIG, TargetType.SCRIPT),
    engine="regex",
), patterns=[
    r"(?:requets|reqeusts|requsts|requersts|requiests|request[^s\W])",
    r"(?:colorsama|colourama|colorma|colorsoma)",
    r"(?:crytpography|cryptograpy|cryptogrpahy)",
    r"pip\s+install\s+(?:requets|reqeusts|requsts|colorsama|colorsoma|crytpography)",
])

# SR-SUPPLY-003: Unpinned dependency + network fetch
register(Rule(
    rule_id="SR-SUPPLY-003",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.MEDIUM,
    title="Unpinned dependency with network fetch",
    description="Installing packages without version pinning combined with network operations.",
    recommendation="Pin dependency versions to prevent supply chain attacks.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"pip\s+install\s+(?!.*==)(?!.*~=)(?!-r\s)(?!-e\s)\w+",
    r"npm\s+install\s+(?!.*@\d)(?!--save-exact)\w+",
])

# SR-SUPPLY-004: Runtime dynamic dependency installation
register(Rule(
    rule_id="SR-SUPPLY-004",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.HIGH,
    title="Runtime dynamic dependency installation",
    description="Installing packages dynamically at runtime via subprocess or os.system.",
    recommendation="Declare dependencies statically; avoid runtime pip/npm install.",
    targets=(TargetType.SCRIPT,),
    engine="regex",
), patterns=[
    r"(?:subprocess|os\.system|os\.popen)\s*\(.*(?:pip|npm|yarn)\s+install",  # noqa: S
    r"__import__\s*\(\s*['\"]pip['\"]\s*\)",
    r"importlib\.import_module\s*\(.*\binstall\b",
])

# SR-SUPPLY-005: postinstall hook fetching from URL
register(Rule(
    rule_id="SR-SUPPLY-005",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.HIGH,
    title="Package install hook fetching remote code",
    description="Package install hook downloads and executes code from a remote URL.",
    recommendation="Install hooks should not fetch code from external URLs.",
    targets=(TargetType.CONFIG, TargetType.SCRIPT),
    engine="regex",
), patterns=[
    r'"(?:post|pre)install"\s*:\s*"[^"]*(?:curl|wget|fetch|http|https)',
    r'"(?:post|pre)install"\s*:\s*"[^"]*(?:node\s+-e|eval\b)',
    r"(?:post_install|pre_install).*(?:urlopen|requests\.get|urllib)",
])

# SR-SUPPLY-006: Expanded typosquatting patterns
register(Rule(
    rule_id="SR-SUPPLY-006",
    category=ThreatCategory.SUPPLY_CHAIN,
    severity=Severity.MEDIUM,
    title="Possible typosquatting package name",
    description="Package name closely resembles a popular package but with subtle misspelling.",
    recommendation="Double-check package name against the official registry.",
    targets=(TargetType.CONFIG, TargetType.SCRIPT),
    engine="regex",
), patterns=[
    r"\b(?:flaask|flaski|flaskk|fIask)\b",
    r"\b(?:djanog|djanggo|djnago|djang0)\b",
    r"\b(?:numpi|numpyy|nuumpy|nunpy)\b",
    r"\b(?:pandsa|pandass|panddas|pnadas)\b",
    r"\b(?:pytorh|torc[^h\W])\b",
    r"\b(?:beautifulsoupp|beautifuIsoup|bs44)\b",
    r"\b(?:sckit-learn|scikit-lern)\b",
    r"\b(?:matplotilib|matplotlb|matplotib)\b",
])
