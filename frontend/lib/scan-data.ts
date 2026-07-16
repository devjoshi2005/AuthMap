export type ModeId = "awsIam" | "gcpIam" | "costData" | "auditLogs";

export type StepOutput = {
  step: string;
  title: string;
  detail: string;
  href?: string;
  ctaLabel?: string;
};

export type ScanMode = {
  id: ModeId;
  label: string;
  title: string;
  format: string;
  description: string;
  coverageSummary: string;
  inputLabel: string;
  placeholder: string;
  sampleInput: string;
  emptyHint: string;
  safeguards: string[];
  allowsFileUpload?: boolean;
  fileAccept?: string;
  stepOutputs: StepOutput[];
};

export const navigationItems = [
  { href: "/", label: "Dashboard" },
  { href: "/guide", label: "Guide" },
  { href: "/scan-wizard", label: "Scan Wizard" },
  { href: "/graph", label: "Graph" },
  { href: "/findings", label: "Findings" },
  { href: "/cost-matrix", label: "Cost Matrix" },
  { href: "/reports", label: "Reports" },
];

export const scanModes: ScanMode[] = [
  {
    id: "awsIam",
    label: "Mode 1",
    title: "AWS IAM Config",
    format: "JSON / CSV",
    description:
      "Import AWS IAM policies, users, roles, and groups. AuthMap parses the trust relationships and builds a graph for privilege escalation analysis.",
    coverageSummary:
      "Full coverage for static policy analysis, managed policy checks, and Rhino Security Labs 16-method escalation detection on AWS.",
    inputLabel: "AWS IAM input",
    placeholder:
      "Paste IAM policy JSON, user/role listings, or attached policy documents here.",
    sampleInput: [
      "{",
      '  "Version": "2012-10-17",',
      '  "Statement": [{',
      '    "Effect": "Allow",',
      '    "Action": "iam:PassRole",',
      '    "Resource": "*"',
      "  }]",
      "}",
    ].join("\n"),
    emptyHint: "No IAM config imported. The dashboard shows a dry preview of the analysis pipeline.",
    safeguards: [
      "Read-only parsing",
      "No AWS API calls",
      "Local graph build",
    ],
    allowsFileUpload: true,
    fileAccept: ".json,.csv,.txt,.yaml,.yml",
    stepOutputs: [
      {
        step: "01",
        title: "Static Policy Analysis",
        detail:
          "Evaluates IAM policies against Rhino Security Labs 16 known privilege escalation methods plus AWS managed policy risk patterns.",
      },
      {
        step: "02",
        title: "Graph Relationship Mapping",
        detail:
          "Builds a Neo4j-compatible graph of users, roles, groups, and policies. Maps trust chains, role assumptions, and cross-account paths.",
      },
      {
        step: "03",
        title: "Anomaly Detection",
        detail:
          "Runs Node2vec embeddings and Local Outlier Factor on the IAM graph to surface structurally unusual permission clusters.",
      },
      {
        step: "04",
        title: "Risk Score Computation",
        detail:
          "Applies the hybrid quadratic formula — MAX(w₁S, w₂G, w₃T, w₄C) × 0.6 + √(w₁S² + w₂G² + w₃T² + w₄C²) × 0.4 — to produce a 0-100 severity score.",
      },
      {
        step: "05",
        title: "Compliance Mapping",
        detail:
          "Auto-maps findings to SOC 2 (CC6.1, CC6.2), RBI (7.1, 7.2), and DPDP Act (Section 8) controls for audit readiness.",
        href: "/findings",
        ctaLabel: "View findings",
      },
      {
        step: "06",
        title: "Report Generation",
        detail:
          "Packages the full analysis into a downloadable report with attack path diagrams, risk scores, and remediation priorities.",
        href: "/reports",
        ctaLabel: "Open reports",
      },
    ],
  },
  {
    id: "gcpIam",
    label: "Mode 2",
    title: "GCP IAM Config",
    format: "JSON / YAML",
    description:
      "Import GCP IAM bindings, service accounts, and custom roles. AuthMap maps the permission hierarchy and detects lateral movement paths.",
    coverageSummary:
      "Full coverage for GCP-specific escalation paths including service account impersonation, role binding abuse, and org-level policy gaps.",
    inputLabel: "GCP IAM input",
    placeholder:
      "Paste GCP IAM policy bindings, service account keys, or role definitions here.",
    sampleInput: [
      "bindings:",
      "  - role: roles/iam.serviceAccountTokenCreator",
      "    members:",
      "      - serviceAccount:dev-sa@project.iam.gserviceaccount.com",
      "  - role: roles/owner",
      "    members:",
      "      - user:admin@company.com",
    ].join("\n"),
    emptyHint: "No GCP config imported. The pipeline shows a dry preview without live data.",
    safeguards: [
      "Read-only parsing",
      "No GCP API calls",
      "Local graph build",
    ],
    allowsFileUpload: true,
    fileAccept: ".json,.yaml,.yml,.txt",
    stepOutputs: [
      {
        step: "01",
        title: "Static Binding Analysis",
        detail:
          "Evaluates GCP IAM bindings for overly permissive roles, service account key exposure, and org-level policy inheritance gaps.",
      },
      {
        step: "02",
        title: "Graph Relationship Mapping",
        detail:
          "Builds a graph of service accounts, users, groups, and role bindings. Maps impersonation chains and cross-project access paths.",
      },
      {
        step: "03",
        title: "Anomaly Detection",
        detail:
          "Runs Node2vec embeddings and LOF on the GCP IAM graph to detect structurally unusual permission patterns and dormant admin accounts.",
      },
      {
        step: "04",
        title: "Risk Score Computation",
        detail:
          "Applies the hybrid quadratic formula to compute per-entity risk scores with weighted inputs from static, graph, temporal, and cost layers.",
      },
      {
        step: "05",
        title: "Compliance Mapping",
        detail:
          "Maps GCP-specific findings to SOC 2, RBI, and DPDP compliance controls with gap analysis for each framework.",
        href: "/findings",
        ctaLabel: "View findings",
      },
      {
        step: "06",
        title: "Report Generation",
        detail:
          "Generates a comprehensive report with GCP attack paths, risk heatmaps, and prioritized remediation steps.",
        href: "/reports",
        ctaLabel: "Open reports",
      },
    ],
  },
  {
    id: "costData",
    label: "Mode 3",
    title: "Cost data",
    format: "CSV / JSON",
    description:
      "Import AWS Cost Explorer or GCP Billing data. AuthMap correlates cloud spend with security risk to identify resources that are both expensive and dangerous.",
    coverageSummary:
      "Enables the cost-security correlation layer (Layer C). Identifies zombie resources, unused admin-attached instances, and cost anomalies tied to risky IAM.",
    inputLabel: "Cost data input",
    placeholder:
      "Paste Cost Explorer CSV, GCP Billing JSON, or cost allocation tags here.",
    sampleInput: [
      "resource_id,service,monthly_cost_usd,last_active",
      "i-0a1b2c3d4e5f,EC2,847.20,2025-01-15",
      "arn:aws:s3:::public-data-dump,S3,234.50,2026-06-01",
      "sa-unused-admin@proj.iam,IAM,0.00,2024-08-22",
    ].join("\n"),
    emptyHint: "No cost data imported. The cost-security correlation layer remains in preview mode.",
    safeguards: [
      "No billing API calls",
      "Statistical analysis only",
      "Z-score anomaly detection",
    ],
    allowsFileUpload: true,
    fileAccept: ".csv,.json,.txt",
    stepOutputs: [
      {
        step: "01",
        title: "Cost Normalization",
        detail:
          "Parses and normalizes cost data across AWS and GCP formats. Tags each resource with service type, cost tier, and last-active timestamp.",
      },
      {
        step: "02",
        title: "Zombie Resource Detection",
        detail:
          "Identifies resources with active cost footprint but no recent usage — EC2 instances, S3 buckets, and service accounts burning budget silently.",
      },
      {
        step: "03",
        title: "Cost Anomaly Scoring",
        detail:
          "Applies Statistical Process Control (Z-scores) to flag spending spikes that may indicate compromised resources or unauthorized provisioning.",
      },
      {
        step: "04",
        title: "Cost-Risk Correlation",
        detail:
          "Cross-references cost data with IAM risk scores. Generates the 4-quadrant scatter plot — Cost (X) vs Risk (Y) — highlighting expensive AND risky resources.",
      },
      {
        step: "05",
        title: "Waste-to-Risk Report",
        detail:
          "Produces actionable findings linking cloud cost waste to security exposure. Prioritizes resources that save money AND reduce attack surface.",
        href: "/findings",
        ctaLabel: "View findings",
      },
      {
        step: "06",
        title: "Executive Summary",
        detail:
          "Packages cost-security insights into a leadership-ready report showing ROI of security remediation through cost savings.",
        href: "/reports",
        ctaLabel: "Open reports",
      },
    ],
  },
  {
    id: "auditLogs",
    label: "Mode 4",
    title: "Audit logs",
    format: "JSON / CloudTrail",
    description:
      "Import CloudTrail or GCP Cloud Audit Logs. AuthMap applies temporal analysis to detect behavioral anomalies and unusual access patterns over time.",
    coverageSummary:
      "Enables the temporal analysis layer (Layer T). Isolation Forest on daily behavior features detects privilege usage spikes, off-hours access, and dormant-then-active patterns.",
    inputLabel: "Audit log input",
    placeholder:
      "Paste CloudTrail events, GCP Audit Log entries, or access log JSON here.",
    sampleInput: [
      '{"eventName": "AssumeRole", "userIdentity": {"type": "IAMUser", "userName": "dev-intern"}, "sourceIPAddress": "203.0.113.50", "eventTime": "2026-06-20T03:14:00Z"}',
      '{"eventName": "CreateAccessKey", "userIdentity": {"type": "IAMUser", "userName": "dev-intern"}, "eventTime": "2026-06-20T03:15:00Z"}',
    ].join("\n"),
    emptyHint:
      "No audit logs imported. The temporal analysis layer stays in preview mode until log data is provided.",
    safeguards: [
      "Read-only parsing",
      "No CloudWatch calls",
      "Local temporal analysis",
    ],
    allowsFileUpload: true,
    fileAccept: ".json,.txt,.log,.csv",
    stepOutputs: [
      {
        step: "01",
        title: "Log Ingestion & Parsing",
        detail:
          "Normalizes CloudTrail and GCP Audit Log formats into a unified event stream. Extracts principal, action, resource, timestamp, and source IP.",
      },
      {
        step: "02",
        title: "Behavioral Baseline",
        detail:
          "Builds per-identity behavioral profiles from daily features — API call frequency, unique actions, access hours, and resource diversity.",
      },
      {
        step: "03",
        title: "Temporal Anomaly Detection",
        detail:
          "Runs Isolation Forest on daily behavior features to flag unusual spikes — off-hours admin access, dormant accounts suddenly active, or rapid privilege changes.",
      },
      {
        step: "04",
        title: "Attack Sequence Matching",
        detail:
          "Correlates temporal anomalies with known privilege escalation sequences. Flags multi-step attack chains like recon → role assumption → key creation.",
      },
      {
        step: "05",
        title: "Temporal Risk Scoring",
        detail:
          "Feeds temporal signals into the hybrid quadratic risk formula as Layer T (20% weight). Updates per-identity risk scores with behavioral evidence.",
        href: "/findings",
        ctaLabel: "View findings",
      },
      {
        step: "06",
        title: "Incident Timeline Report",
        detail:
          "Generates a chronological incident report with annotated attack timelines, anomaly highlights, and recommended investigation steps.",
        href: "/reports",
        ctaLabel: "Open reports",
      },
    ],
  },
];

export const securityModules = [
  {
    label: "IAM Graph Engine",
    summary: "Interactive Cytoscape.js visualization of IAM entity relationships across AWS and GCP.",
  },
  {
    label: "Privilege Escalation Detection",
    summary: "4-layer analysis: Static (40%) + Graph (30%) + Temporal (20%) + Cost (10%) scoring.",
  },
  {
    label: "Cost-Security Correlation",
    summary: "Scatter-plot quadrant mapping of cloud spend against IAM risk scores.",
  },
  {
    label: "Compliance Mapping",
    summary: "Auto-mapping to SOC 2, RBI, and DPDP Act frameworks with gap analysis.",
  },
  {
    label: "Hybrid Risk Scoring",
    summary: "Quadratic formula combining worst-case and multi-factor compounding into 0-100 severity.",
  },
] as const;

export const moduleLabels = securityModules.map((module) => module.label);

export const scanDetailCards = [
  {
    label: "Analysis scope",
    value: "Multi-cloud IAM",
    note: "Import up to 4 data sources: AWS IAM, GCP IAM, cost data, and audit logs for comprehensive coverage.",
  },
  {
    label: "Detection layers",
    value: "4-layer SGTC model",
    note: "Static policy checks, graph-based anomalies, temporal behavioral analysis, and cost-security correlation.",
  },
  {
    label: "Risk formula",
    value: "Hybrid quadratic scoring",
    note: "MAX(worst factor) × 0.6 + √(sum of squares) × 0.4 prevents single-factor dilution while capturing compound risk.",
  },
];

export const findingsSummary = [
  {
    severity: "Critical",
    title: "Admin privilege escalation path detected",
    summary: "A chain of IAM permissions allows lateral movement from a low-privilege user to administrative access through role assumption or policy attachment.",
  },
  {
    severity: "High",
    title: "Cross-account role chain exploitable",
    summary: "Trust policies enable cross-account role assumption without MFA enforcement, creating a potential lateral movement vector between AWS accounts.",
  },
  {
    severity: "Medium",
    title: "Unused admin keys with active cost footprint",
    summary: "Service accounts or IAM users with admin-level access keys show no recent API activity but are attached to resources generating ongoing costs.",
  },
  {
    severity: "Medium",
    title: "Compliance gap in access control mapping",
    summary: "IAM configurations do not fully satisfy SOC 2 CC6.1 least-privilege requirements or RBI 7.1 access control mandates.",
  },
];

export const reportSections = [
  {
    title: "Executive summary",
    body: "A leadership-ready overview of IAM risk posture, privilege escalation paths detected, cost-security correlation highlights, and compliance gap analysis.",
  },
  {
    title: "Attack path analysis",
    body: "Detailed graph-based visualization of privilege escalation chains with per-path risk scores, affected entities, and exploitation difficulty ratings.",
  },
  {
    title: "Remediation roadmap",
    body: "Prioritized action items: remove excessive permissions, rotate unused keys, enforce MFA on cross-account roles, and decommission zombie resources.",
  },
];