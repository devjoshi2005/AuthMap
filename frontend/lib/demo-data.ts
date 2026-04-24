export type ModeId = "config" | "endpoint" | "code";

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
    id: "config",
    label: "Mode 1",
    title: "Config file",
    format: "YAML / JSON",
    description:
      "Paste a config file payload for safe parsing, schema checks, and sanitized demo routing.",
    inputLabel: "Config input",
    placeholder:
      "Paste YAML or JSON here. Leave it empty to preview the pipeline with a dry run.",
    sampleInput: [
      "agent_name: support-bot",
      "rag_enabled: true",
      "tools:",
      "  - name: searchDocs",
      "  - name: sendEmail",
    ].join("\n"),
    emptyHint: "No file pasted. The UI stays in dry-run mode and only previews execution.",
    safeguards: [
      "Safe parsing only",
      "Allowlisted schema keys",
      "5 MB hard cap",
    ],
    allowsFileUpload: true,
    fileAccept: ".yaml,.yml,.json,.txt",
    stepOutputs: [
      {
        step: "01",
        title: "Direct prompt attack check",
        detail:
          "Fires many tricky prompts to see whether the agent leaks hidden rules, changes persona, or obeys unsafe commands.",
      },
      {
        step: "02",
        title: "RAG poisoning check",
        detail:
          "Plants hostile instructions inside test documents and checks whether retrieved content can steer the agent off course.",
      },
      {
        step: "03",
        title: "Prompt leak check",
        detail:
          "Uses leak-focused questions like repeat-above prompts to see if private system instructions slip out.",
      },
      {
        step: "04",
        title: "Tool power check",
        detail:
          "Reviews each tool for access that feels too broad, like delete, write, or execute power when read-only should be enough.",
      },
      {
        step: "05",
        title: "Output safety check",
        detail:
          "Pushes XSS, shell, SQL, HTML, and risky markdown patterns to see whether unsafe output would pass through to users.",
      },
      {
        step: "06",
        title: "MCP exposure check",
        detail:
          "Looks for public tool lists, dangerous tool names, prompt-poisoned descriptions, and weak CORS settings on MCP endpoints.",
      },
      {
        step: "07",
        title: "Remediation plan",
        detail:
          "Builds a short fix list: tighten prompts, reduce permissions, sanitize outputs, and require stronger auth where needed.",
        href: "/findings",
        ctaLabel: "Open remediation",
      },
      {
        step: "08",
        title: "Report",
        detail:
          "Packages the scan summary into a clean report view so users can move from preview to findings and final report pages.",
        href: "/reports",
        ctaLabel: "Open report",
      },
    ],
  },
  {
    id: "endpoint",
    label: "Mode 2",
    title: "Live endpoint",
    format: "HTTP / HTTPS",
    description:
      "Paste an endpoint URL for a bounded demo flow with ownership and network safety checks.",
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
        title: "Remediation plan",
        detail:
          "Turns the scan into clear fixes that product teams can act on without reading raw payload details first.",
        href: "/findings",
        ctaLabel: "Open remediation",
      },
      {
        step: "08",
        title: "Report",
        detail:
          "Pushes the scan outcome into a shareable report view with the main findings, fixes, and next review steps.",
        href: "/reports",
        ctaLabel: "Open report",
      },
    ],
  },
  {
    id: "code",
    label: "Mode 3",
    title: "Python code",
    format: "Static analysis",
    description:
      "Paste Python agent code for AST-based structure review and suspicious import flagging.",
    inputLabel: "Python input",
    placeholder:
      "Paste Python source here. Leave it empty to preview the static analysis flow only.",
    sampleInput: [
      "from langchain.agents import AgentExecutor",
      "tools = [search_tool, email_tool]",
      "system_prompt = \"Respond safely\"",
    ].join("\n"),
    emptyHint: "No source pasted. The UI still shows the static-analysis pipeline in preview mode.",
    safeguards: [
      "AST parsing only",
      "No exec or eval",
      "Suspicious import flags",
    ],
    allowsFileUpload: true,
    fileAccept: ".py,.txt,.md",
    stepOutputs: [
      {
        step: "01",
        title: "Direct prompt attack check",
        detail:
          "Maps prompt-handling code paths to see whether direct injection risks are likely before runtime even starts.",
      },
      {
        step: "02",
        title: "RAG poisoning check",
        detail:
          "Looks for retrieval logic that could mistakenly trust document text as system-level instructions.",
      },
      {
        step: "03",
        title: "Prompt leak check",
        detail:
          "Searches prompt templates, role text, and agent setup patterns that could expose hidden instructions.",
      },
      {
        step: "04",
        title: "Tool power check",
        detail:
          "Finds tool access, permission scope, and irreversible actions that look larger than the agent’s job requires.",
      },
      {
        step: "05",
        title: "Output safety check",
        detail:
          "Flags places where model output may reach a browser, terminal, or database without enough cleaning first.",
      },
      {
        step: "06",
        title: "MCP exposure check",
        detail:
          "Checks whether connected MCP usage might expose tools, descriptions, or unauthenticated access routes.",
      },
      {
        step: "07",
        title: "Remediation plan",
        detail:
          "Summarizes the main fixes: safer prompt boundaries, smaller tool scope, cleaner output handling, and stricter access rules.",
        href: "/findings",
        ctaLabel: "Open remediation",
      },
      {
        step: "08",
        title: "Report",
        detail:
          "Assembles a readable report page with highlighted risks, reasoning, and next review checkpoints.",
        href: "/reports",
        ctaLabel: "Open report",
      },
    ],
  },
];

export const moduleLabels = [
  "Direct prompt injection",
  "Indirect prompt injection",
  "System prompt extraction",
  "Excessive agency checker",
  "Insecure output handling",
  "MCP server exposure",
];

export const scanDetailCards = [
  {
    label: "Default demo mode",
    value: "Config file scan",
    note: "Editable on the overview screen with no backend dependency.",
  },
  {
    label: "Execution type",
    value: "Frontend dry run",
    note: "The pipeline now shows eight visible stages from attack checks through remediation and final report handoff.",
  },
  {
    label: "Core guardrails",
    value: "Parse-only, bounded, static",
    note: "All three modes are framed around non-destructive validation paths.",
  },
];

export const findingsSummary = [
  {
    severity: "High",
    title: "Prompt injection resistance is unverified",
    summary: "The demo flow keeps direct and indirect injection checks prominent in the output pipeline.",
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