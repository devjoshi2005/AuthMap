export type ModeId = "config" | "endpoint" | "code" | "modelCard";

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
  { href: "/", label: "Overview" },
  { href: "/scan-details", label: "Scan details" },
  { href: "/findings", label: "Findings" },
  { href: "/reports", label: "Reports" },
];

export const scanModes: ScanMode[] = [
  {
    id: "endpoint",
    label: "Mode 2",
    title: "Live endpoint",
    format: "HTTP / HTTPS",
    description:
      "Paste an endpoint URL for a bounded scan flow with ownership and network safety checks.",
    coverageSummary:
      "Best for runtime checks like prompt injection, prompt leaks, and output safety. Adds live signal to tool and MCP checks.",
    inputLabel: "Endpoint input",
    placeholder:
      "Paste an HTTPS endpoint. Leave it empty to preview the UI without a live target.",
    sampleInput: [
      "Target URL: https://agent.example.com/api/chat",
      "Ownership confirmed: true",
      "Request timeout: 30s",
    ].join("\n"),
    emptyHint: "No endpoint pasted. The UI shows a dry preview without any request activity.",
    safeguards: [
      "Strict URL validation",
      "Private IP blocking",
      "5 minute rate limit",
    ],
    stepOutputs: [
      {
        step: "01",
        title: "Direct prompt attack check",
        detail:
          "Sends injection prompts to the live endpoint and asks a judge model whether the agent gave in.",
      },
      {
        step: "02",
        title: "RAG poisoning check",
        detail:
          "Tests whether retrieved documents can quietly override the agent when external knowledge is in play.",
      },
      {
        step: "03",
        title: "Prompt leak check",
        detail:
          "Runs leakage prompts to see whether the endpoint exposes hidden setup or internal instruction text.",
      },
      {
        step: "04",
        title: "Tool power check",
        detail:
          "Checks whether the endpoint appears to have more write, delete, or execute ability than its stated role needs.",
      },
      {
        step: "05",
        title: "Output safety check",
        detail:
          "Tries to provoke unsafe browser, shell, SQL, and HTML output that could become a real rendering issue.",
      },
      {
        step: "06",
        title: "MCP exposure check",
        detail:
          "Probes attached MCP surfaces for open tool access, risky names, and endpoint security gaps.",
      },
      {
        step: "07",
        title: "Compliance check",
        detail:
          "Flags endpoints that appear to serve regulated or restricted workflows without matching disclaimers, consent gates, or operator controls.",
      },
      {
        step: "08",
        title: "Remediation plan",
        detail:
          "Turns the scan into clear fixes that product teams can act on without reading raw payload details first.",
        href: "/findings",
        ctaLabel: "Open remediation",
      },
      {
        step: "09",
        title: "Report",
        detail:
          "Pushes the scan outcome into a shareable report view with the main findings, fixes, and next review steps.",
        href: "/reports",
        ctaLabel: "Open report",
      },
    ],
  }
];

export const securityModules = [
  {
    label: "Direct prompt injection",
    summary: "Runtime attempts to override or hijack agent instructions.",
  },
  {
    label: "Indirect prompt injection",
    summary: "Retrieved or embedded content that quietly steers the model.",
  },
  {
    label: "System prompt extraction",
    summary: "Leaking hidden system instructions, rules, or role text.",
  },
  {
    label: "Excessive agency checker",
    summary: "Tools and actions that exceed the agent's stated purpose.",
  },
  {
    label: "Insecure output handling",
    summary: "Unsafe model output reaching browsers, shells, or databases.",
  },
  {
    label: "MCP server exposure",
    summary: "Risky tool servers, open RPC surfaces, or poisoned tool metadata.",
  },
  {
    label: "Compliance check",
    summary: "Policy, intended-use, provenance, and license conflicts before deployment.",
  },
] as const;

export const moduleLabels = securityModules.map((module) => module.label);

export const scanDetailCards = [
  {
    label: "Default scan mode",
    value: "Multi-input scan",
    note: "Pick 1 to 4 inputs on the overview screen: config, endpoint, Python code, or model card.",
  },
  {
    label: "Execution type",
    value: "Frontend dry run",
    note: "The pipeline now shows nine visible stages, adding compliance review before remediation and final report handoff.",
  },
  {
    label: "Core guardrails",
    value: "Parse-only, bounded, static",
    note: "All four modes stay non-destructive and focus on bounded validation signals rather than live exploitation.",
  },
];

export const findingsSummary = [
  {
    severity: "High",
    title: "Prompt injection resistance is unverified",
    summary: "The scan flow keeps direct and indirect injection checks prominent in the output pipeline.",
  },
  {
    severity: "Medium",
    title: "Tool permissions need explicit review",
    summary: "The agency checker remains visible because write, delete, and exec access need purpose alignment.",
  },
  {
    severity: "Medium",
    title: "Unsafe output rendering needs guardrails",
    summary: "Output handling stays in scope for browser, terminal, and SQL-shaped payloads.",
  },
  {
    severity: "Medium",
    title: "Compliance drift needs explicit review",
    summary: "Model cards, licenses, and intended-use limits can conflict with what the product is actually shipping.",
  },
];

export const reportSections = [
  {
    title: "Executive summary",
    body: "A compact, frontend-only report surface that explains the scan mode, pipeline status, and high-level risk posture.",
  },
  {
    title: "Evidence bundle",
    body: "A section reserved for payload traces, response excerpts, import flags, and tool manifests once backend data exists.",
  },
  {
    title: "Recommended actions",
    body: "A checklist-style area for tightening parsing, reducing tool access, sanitizing output, and gating MCP exposure.",
  },
];