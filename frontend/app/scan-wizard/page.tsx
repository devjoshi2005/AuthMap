"use client";

import { useAuth, useUser } from "@clerk/nextjs";
import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";

type CloudProvider = "aws" | "gcp";
type WizardStep = "provider" | "credentials" | "scope" | "neo4j" | "launch";

const COST_REGIONS = [
  { value: "INDIA", label: "India" },
  { value: "US", label: "US" },
  { value: "EU", label: "EU" },
  { value: "UK", label: "UK" },
  { value: "MIDDLE_EAST", label: "Middle East" },
  { value: "CANADA", label: "Canada" },
  { value: "BRAZIL", label: "Brazil" },
];

const AWS_REGIONS = [
  { value: "us-east-1", label: "us-east-1 (N. Virginia)" },
  { value: "us-east-2", label: "us-east-2 (Ohio)" },
  { value: "us-west-1", label: "us-west-1 (N. California)" },
  { value: "us-west-2", label: "us-west-2 (Oregon)" },
  { value: "af-south-1", label: "af-south-1 (Cape Town)" },
  { value: "ap-east-1", label: "ap-east-1 (Hong Kong)" },
  { value: "ap-south-1", label: "ap-south-1 (Mumbai)" },
  { value: "ap-south-2", label: "ap-south-2 (Hyderabad)" },
  { value: "ap-northeast-3", label: "ap-northeast-3 (Osaka)" },
  { value: "ap-northeast-2", label: "ap-northeast-2 (Seoul)" },
  { value: "ap-southeast-1", label: "ap-southeast-1 (Singapore)" },
  { value: "ap-southeast-2", label: "ap-southeast-2 (Sydney)" },
  { value: "ap-southeast-3", label: "ap-southeast-3 (Jakarta)" },
  { value: "ap-southeast-4", label: "ap-southeast-4 (Melbourne)" },
  { value: "ap-northeast-1", label: "ap-northeast-1 (Tokyo)" },
  { value: "ca-central-1", label: "ca-central-1 (Central)" },
  { value: "ca-west-1", label: "ca-west-1 (Calgary)" },
  { value: "eu-central-1", label: "eu-central-1 (Frankfurt)" },
  { value: "eu-west-1", label: "eu-west-1 (Ireland)" },
  { value: "eu-west-2", label: "eu-west-2 (London)" },
  { value: "eu-south-1", label: "eu-south-1 (Milan)" },
  { value: "eu-south-2", label: "eu-south-2 (Spain)" },
  { value: "eu-west-3", label: "eu-west-3 (Paris)" },
  { value: "eu-north-1", label: "eu-north-1 (Stockholm)" },
  { value: "eu-central-2", label: "eu-central-2 (Zurich)" },
  { value: "il-central-1", label: "il-central-1 (Tel Aviv)" },
  { value: "me-south-1", label: "me-south-1 (Bahrain)" },
  { value: "me-central-1", label: "me-central-1 (UAE)" },
  { value: "sa-east-1", label: "sa-east-1 (São Paulo)" }
];

const COMPLIANCE_FRAMEWORKS = [
  { value: "SOC2", label: "SOC 2" },
  { value: "DPDP", label: "DPDP" },
  { value: "RBI", label: "RBI" },
  { value: "PCI_DSS", label: "PCI-DSS" },
  { value: "GDPR", label: "GDPR" },
  { value: "HIPAA", label: "HIPAA" },
  { value: "IRDAI", label: "IRDAI" },
  { value: "SEBI", label: "SEBI" },
  { value: "IT_ACT", label: "IT Act" },
];

type ScanStatus = {
  scan_id: number;
  status: "pending" | "discovery" | "graph_building" | "risk_scoring" | "reporting" | "completed" | "failed";
  progress: number;
  phase?: string;
  error?: string;
};

export default function ScanWizardPage() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const [step, setStep] = useState<WizardStep>("provider");
  const [provider, setProvider] = useState<CloudProvider>("aws");

  // AWS: Cross-Account Role
  const [awsAccountId, setAwsAccountId] = useState("");
  const [awsRoleArn, setAwsRoleArn] = useState("");
  const [awsExternalId, setAwsExternalId] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");

  // GCP: Service Account JSON
  const [gcpSaJson, setGcpSaJson] = useState("");
  const [gcpProjectId, setGcpProjectId] = useState("");

  // Neo4j Database
  const [neo4jUri, setNeo4jUri] = useState("");
  const [neo4jUser, setNeo4jUser] = useState("");
  const [neo4jPassword, setNeo4jPassword] = useState("");

  const [isLaunching, setIsLaunching] = useState(false);
  const [launchResult, setLaunchResult] = useState<string | null>(null);

  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  // Scope
  const [costRegion, setCostRegion] = useState("INDIA");
  const [annualRevenue, setAnnualRevenue] = useState("");
  const [compliances, setCompliances] = useState<string[]>(["SOC2", "DPDP"]);

  // Scan progress polling state
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const steps: { id: WizardStep; label: string; num: string }[] = [
    { id: "provider", label: "Provider", num: "1" },
    { id: "credentials", label: "Connect", num: "2" },
    { id: "scope", label: "Scope", num: "3" },
    { id: "neo4j", label: "Database", num: "4" },
    { id: "launch", label: "Launch", num: "5" },
  ];

  const currentStepIndex = steps.findIndex((s) => s.id === step);

  // Generate a stable ExternalID per session for AWS CloudFormation
  useEffect(() => {
    if (user?.id) {
      setAwsExternalId(`authmap-${user.id}`);
    }
  }, [user?.id]);

  const contentRef = useRef<HTMLDivElement>(null);

  // Clean up polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, []);

  // Auto-scroll to content when step changes
  useEffect(() => {
    const timer = setTimeout(() => {
      if (contentRef.current) {
        contentRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 150);
    return () => clearTimeout(timer);
  }, [step]);


  // Hydrate from sessionStorage
  useEffect(() => {
    const saved = localStorage.getItem('boxai_scan_creds');
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.provider) setProvider(data.provider);
        if (data.awsAccountId) setAwsAccountId(data.awsAccountId);
        if (data.awsRoleArn) setAwsRoleArn(data.awsRoleArn);
        if (data.awsRegion) setAwsRegion(data.awsRegion);
        if (data.gcpProjectId) setGcpProjectId(data.gcpProjectId);
        if (data.costRegion) setCostRegion(data.costRegion);
        if (data.annualRevenue) setAnnualRevenue(data.annualRevenue);
        if (data.compliances) setCompliances(data.compliances);
        // Neo4j credentials intentionally not hydrated here per user request to start empty
      } catch (e) {}
    }
  }, []);

  // Save to sessionStorage (gcpSaJson is deliberately excluded for security)
  useEffect(() => {
    const creds = {
      provider, awsAccountId, awsRoleArn, awsRegion, gcpProjectId,
      costRegion, annualRevenue, compliances, neo4jUri, neo4jUser, neo4jPassword
    };
    localStorage.setItem('boxai_scan_creds', JSON.stringify(creds));
  }, [provider, awsAccountId, awsRoleArn, awsRegion, gcpProjectId, costRegion, annualRevenue, compliances, neo4jUri, neo4jUser, neo4jPassword]);

  const startPolling = useCallback(
    (scanId: number) => {
      setIsPolling(true);
      const poll = async () => {
        try {
          const token = await getToken();
          if (!token) return; // Wait until token is available to avoid 401 Unauthorized errors
          
          const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
          const res = await fetch(`${backendUrl}/scan/status/${scanId}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (res.ok) {
            const data = await res.json();
            setScanStatus((prev) => ({
              scan_id: scanId,
              status: data.status || prev?.status || "pending",
              progress: data.progress ?? prev?.progress ?? 0,
              phase: data.phase || prev?.phase,
              error: data.error || undefined,
            }));
            
            if (data.status === "completed") {
              if (pollingRef.current) clearInterval(pollingRef.current);
              setIsPolling(false);
              
              // ── Client-Side RAG Ingestion ──
              try {
                const findingsRes = await fetch(`${backendUrl}/scan/findings/${scanId}`, {
                  headers: { Authorization: `Bearer ${token}` }
                });
                if (findingsRes.ok) {
                  const findingsData = await findingsRes.json();
                  const findingsList = Array.isArray(findingsData) ? findingsData : findingsData.findings || [];
                  const { clientRAGEngine } = await import("@/lib/rag/client-rag-engine");
                  
                  // Retrieve provider from config
                  let scanCloud = "unknown";
                  try {
                    const cfg = sessionStorage.getItem("boxai_scan_config");
                    if (cfg) scanCloud = JSON.parse(cfg).provider || "unknown";
                  } catch (e) {}
                  
                  await clientRAGEngine.ingestScanTelemetry(String(scanId), scanCloud, findingsList);
                }
              } catch (ragErr) {
                console.error("Failed to ingest scan into Client RAG", ragErr);
              }

            } else if (data.status === "failed") {
              if (pollingRef.current) clearInterval(pollingRef.current);
              setIsPolling(false);
            }
          }
        } catch {}
      };
      poll();
      pollingRef.current = setInterval(poll, 3000);
    },
    [getToken]
  );

  function toggleCompliance(fw: string) {
    setCompliances((prev) =>
      prev.includes(fw) ? prev.filter((c) => c !== fw) : [...prev, fw]
    );
  }

  function canProceed() {
    if (step === "provider") return true;
    if (step === "credentials" && provider === "aws") {
      return awsRoleArn.trim().length > 0;
    }
    if (step === "credentials" && provider === "gcp") {
      return gcpSaJson.trim().length > 0 && gcpProjectId.trim().length > 0;
    }
    if (step === "scope") return true;
    if (step === "neo4j") {
      return neo4jUri.trim().length > 0 && neo4jUser.trim().length > 0 && neo4jPassword.length > 0;
    }
    return false;
  }

  async function goNext() {
    if (step === "credentials") {
      setVerifyError(null);
      
      // Strict regex definitions for input validation
      const awsArnRegex = /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$/;
      const awsExternalIdRegex = /^[\w+=,.@:-]+$/;
      const gcpProjectIdRegex = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

      if (provider === "aws") {
        if (!awsArnRegex.test(awsRoleArn.trim())) {
          setVerifyError("Invalid AWS Role ARN format detected. Please check for special characters or invalid format.");
          return;
        }
        if (awsExternalId && !awsExternalIdRegex.test(awsExternalId)) {
          setVerifyError("Invalid AWS External ID format. Only alphanumeric characters and +=,.@:- are allowed.");
          return;
        }
      }

      if (provider === "gcp") {
        if (!gcpProjectIdRegex.test(gcpProjectId.trim())) {
          setVerifyError("Invalid GCP Project ID format.");
          return;
        }
        try {
          const parsed = JSON.parse(gcpSaJson);
          if (!parsed.type) throw new Error();
        } catch {
          setVerifyError("GCP Service Account Key must be a valid JSON object.");
          return;
        }
      }

      setIsVerifying(true);
      try {
        const token = await getToken();
        const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
        const body = provider === "aws"
          ? { provider: "aws", aws_role_arn: awsRoleArn.trim(), aws_external_id: awsExternalId, region: awsRegion }
          : { provider: "gcp", gcp_sa_json: gcpSaJson, gcp_project_id: gcpProjectId.trim() };
          
        const res = await fetch(`${backendUrl}/scan/verify-credentials`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify(body)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const detail = data?.detail || (typeof data === "string" ? data : `Backend returned status ${res.status}`);
          setVerifyError(typeof detail === "string" ? detail : JSON.stringify(detail));
          setIsVerifying(false);
          return;
        }
        if (!data.valid && data.error) {
          setVerifyError(data.error || "Connection test failed.");
          setIsVerifying(false);
          return;
        }
      } catch (e: any) {
        console.error("Verification error:", e);
        setVerifyError(e?.message ? `Connection failed: ${e.message}` : "Could not reach backend to verify credentials.");
        setIsVerifying(false);
        return;
      }
      setIsVerifying(false);
    }

    if (step === "neo4j") {
      setIsVerifying(true);
      setVerifyError(null);
      try {
        const token = await getToken();
        const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
        const body = { provider: "none", neo4j_uri: neo4jUri.trim(), neo4j_username: neo4jUser.trim(), neo4j_password: neo4jPassword };
          
        const res = await fetch(`${backendUrl}/scan/verify-credentials`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify(body)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const detail = data?.detail || (typeof data === "string" ? data : `Backend returned status ${res.status}`);
          setVerifyError(typeof detail === "string" ? detail : JSON.stringify(detail));
          setIsVerifying(false);
          return;
        }
        if (!data.valid && data.error) {
          setVerifyError(data.error || "Neo4j Connection test failed.");
          setIsVerifying(false);
          return;
        }
      } catch (e: any) {
        console.error("Neo4j verification error:", e);
        setVerifyError(e?.message ? `Neo4j connection failed: ${e.message}` : "Could not reach backend to verify Neo4j credentials.");
        setIsVerifying(false);
        return;
      }
      setIsVerifying(false);
    }

    setVerifyError(null);
    const nextIndex = currentStepIndex + 1;
    if (nextIndex < steps.length) setStep(steps[nextIndex].id);
  }

  function goBack() {
    const prevIndex = currentStepIndex - 1;
    if (prevIndex >= 0) setStep(steps[prevIndex].id);
  }



  async function handleAwsDownloadTemplate() {
    try {
      const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
      const res = await fetch(`${backendUrl}/aws/cloudformation?external_id=${awsExternalId}&account_id=${awsAccountId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch template`);
      
      const templateJson = await res.json();
      const blob = new Blob([JSON.stringify(templateJson, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `authmap-scanner-role-${awsAccountId}-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (e: any) {
      console.error("Download template error:", e);
      setVerifyError(`Could not download CloudFormation template: ${e.message || e}`);
    }
  }

  function handleAwsOpenConsole() {
    const cfnUrl = `https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/template`;
    window.open(cfnUrl, "_blank");
  }

  function handleGcpDownloadRoles() {
    const rolesList = {
      "required_roles": [
        "roles/cloudasset.viewer",
        "roles/cloudsql.admin",
        "roles/iam.roleAdmin",
        "roles/iam.securityReviewer",
        "roles/iam.serviceAccountCreator",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/logging.viewer",
        "roles/resourcemanager.projectIamAdmin",
        "roles/serviceusage.serviceUsageAdmin"
      ]
    };
    const blob = new Blob([JSON.stringify(rolesList, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `authmap-gcp-roles.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  async function handleLaunch() {
    setIsLaunching(true);
    setLaunchResult(null);
    setScanStatus(null);
    try {
      const neo4jUriRegex = /^(neo4j|bolt|neo4j\+s|bolt\+s):\/\/[a-zA-Z0-9.-]+(:\d+)?$/;
      const neo4jUserRegex = /^[a-zA-Z0-9_.-]+$/;

      if (!neo4jUriRegex.test(neo4jUri.trim())) {
        setLaunchResult("Invalid Neo4j URI format. Must start with neo4j:// or bolt:// and contain a valid host.");
        setIsLaunching(false);
        return;
      }
      if (!neo4jUserRegex.test(neo4jUser.trim())) {
        setLaunchResult("Invalid Neo4j Username format. Only alphanumeric and _.- characters are allowed.");
        setIsLaunching(false);
        return;
      }

      const token = await getToken();


      const accountName = user?.fullName || user?.firstName || user?.username || user?.primaryEmailAddress?.emailAddress?.split("@")[0] || "Operator";
      
      const payload: any = {
        provider,
        region: awsRegion,
        cost_region: costRegion,
        annual_revenue: parseFloat(annualRevenue) || undefined,
        selected_compliances: compliances,
        account_name: accountName,
        neo4j_uri: neo4jUri.trim(),
        neo4j_username: neo4jUser.trim(),
        neo4j_password: neo4jPassword
      };

      if (provider === "aws") {
        payload.aws_role_arn = awsRoleArn;
        payload.aws_external_id = awsExternalId;
        if (awsAccountId) payload.aws_account_id = awsAccountId;
      } else if (provider === "gcp") {
        payload.gcp_project_id = gcpProjectId;
        payload.gcp_sa_json = gcpSaJson;
      }

      try {
        const sanitizedConfig = {
          provider,
          region: awsRegion,
          cost_region: costRegion,
          annual_revenue: parseFloat(annualRevenue) || undefined,
          selected_compliances: compliances,
          account_name: accountName,
          aws_role_arn: awsRoleArn || undefined,
          aws_account_id: awsAccountId || undefined,
          gcp_project_id: gcpProjectId || undefined,
        };
        sessionStorage.setItem("boxai_scan_config", JSON.stringify(sanitizedConfig));
      } catch (e) {}

      const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
      const res = await fetch(`${backendUrl}/scan/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.scan_id) {
          try {
            sessionStorage.setItem("boxai_last_scan_id", String(data.scan_id));
          } catch (e) {}
          setScanStatus({ scan_id: data.scan_id, status: data.status || "pending", progress: 0 });
          startPolling(data.scan_id);
        } else {
          setLaunchResult("Analysis launched successfully. Results will appear in Findings and Graph views.");
        }
      } else {
        setLaunchResult("Failed to launch analysis. Check backend connection.");
      }
    } catch {
      setLaunchResult("Could not reach backend server.");
    } finally {
      setIsLaunching(false);
    }
  }

  function getPhaseLabel(status: string): string {
    switch (status) {
      case "pending": return "Queued…";
      case "discovery": return "Discovering IAM entities…";
      case "graph_building": return "Building relationship graph…";
      case "risk_scoring": return "Computing risk scores…";
      case "reporting": return "Generating reports…";
      case "completed": return "Scan completed!";
      case "failed": return "Scan failed.";
      default: return status;
    }
  }

  function getProgressPercent(status: string, progress: number): number {
    if (progress > 0) return progress;
    switch (status) {
      case "pending": return 5;
      case "discovery": return 25;
      case "graph_building": return 50;
      case "risk_scoring": return 75;
      case "reporting": return 90;
      case "completed": return 100;
      case "failed": return 0;
      default: return 0;
    }
  }

  return (
    <AppShell>
      <div className="space-y-8 pb-10" ref={contentRef}>
        <ScreenHeader
          eyebrow="Scan Wizard"
          title="Connect. Configure. Launch."
          description="Three steps to a full IAM attack path analysis across your cloud environment."
        />

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2">
          {steps.map((s, i) => (
            <div key={s.id} className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => { if (i <= currentStepIndex) setStep(s.id); }}
                className={`flex h-9 w-9 items-center justify-center rounded-full text-sm font-bold transition ${
                  i === currentStepIndex
                    ? "border-2 border-[var(--accent-cyan)] bg-[rgba(158,193,182,0.15)] text-white"
                    : i < currentStepIndex
                    ? "border border-white/20 bg-white/[0.08] text-white"
                    : "border border-white/10 bg-white/[0.03] text-slate-500"
                }`}
              >
                {i < currentStepIndex ? "✓" : s.num}
              </button>
              <span className={`hidden text-xs font-medium uppercase tracking-wider sm:inline ${
                i === currentStepIndex ? "text-white" : i < currentStepIndex ? "text-slate-300" : "text-slate-500"
              }`}>
                {s.label}
              </span>
              {i < steps.length - 1 && (
                <div className={`mx-1 h-px w-8 sm:w-12 ${
                  i < currentStepIndex ? "bg-white/20" : "bg-white/8"
                }`} />
              )}
            </div>
          ))}
        </div>

        {/* Step content */}
        <section className="mx-auto max-w-2xl rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_50px_rgba(0,0,0,0.18)] md:p-8">

          {step === "provider" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 1</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Choose your cloud provider</h2>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => setProvider("aws")}
                  className={`rounded-[1.2rem] border p-5 text-left transition ${
                    provider === "aws"
                      ? "border-[var(--accent-cyan)]/50 bg-[rgba(158,193,182,0.1)] shadow-[0_12px_30px_rgba(158,193,182,0.06)]"
                      : "border-white/10 bg-white/[0.03] hover:border-white/18"
                  }`}
                >
                  <p className="text-lg font-semibold text-white">Amazon Web Services</p>
                  <p className="mt-1 text-sm text-slate-300">IAM users, roles, policies, groups</p>
                </button>
                <button
                  type="button"
                  onClick={() => setProvider("gcp")}
                  className={`rounded-[1.2rem] border p-5 text-left transition ${
                    provider === "gcp"
                      ? "border-[var(--accent-gold)]/50 bg-[rgba(234,216,178,0.1)] shadow-[0_12px_30px_rgba(234,216,178,0.06)]"
                      : "border-white/10 bg-white/[0.03] hover:border-white/18"
                  }`}
                >
                  <p className="text-lg font-semibold text-white">Google Cloud Platform</p>
                  <p className="mt-1 text-sm text-slate-300">IAM bindings, service accounts, roles</p>
                </button>
              </div>
            </div>
          )}

          {/* ═══════════ AWS CREDENTIALS ═══════════ */}
          {step === "credentials" && provider === "aws" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 2 — AWS</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Connect AWS Account</h2>
                <p className="mt-2 text-sm text-slate-300">Industry-standard cross-account role assumption. No long-lived keys required.</p>
              </div>

              {/* Step A: Launch CloudFormation */}
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5 space-y-4">
                <div className="flex items-center gap-3 border-b border-white/10 pb-4">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--accent-cyan)]/40 bg-[var(--accent-cyan)]/10 text-xs font-bold text-[var(--accent-cyan)]">A</span>
                  <p className="text-sm font-semibold text-white">Deploy the Scanner Role</p>
                </div>
                
                <div className="text-xs text-slate-300 space-y-2 pb-2">
                  <p><span className="font-semibold text-white">1. Enter</span> your AWS Account ID.</p>
                  <p><span className="font-semibold text-white">2. Download</span> the JSON template below.</p>
                  <p><span className="font-semibold text-white">3. Open</span> the AWS CloudFormation Console.</p>
                  <p><span className="font-semibold text-white">4. Upload</span> the file (Create Stack &gt; Upload a template file).</p>
                  <p><span className="font-semibold text-white">5. Copy</span> the resulting Role ARN from the Outputs tab.</p>
                </div>
                
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Your AWS Account ID</label>
                  <input
                    type="text"
                    value={awsAccountId}
                    onChange={(e) => setAwsAccountId(e.target.value.replace(/\D/g, ''))}
                    maxLength={12}
                    placeholder="123456789012"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                  />
                  <p className="mt-1.5 text-xs text-slate-500">12-digit number (used to generate the trust policy for your CloudFormation stack)</p>
                </div>

                <div className="flex flex-col sm:flex-row gap-3">
                  <button
                    type="button"
                    onClick={handleAwsDownloadTemplate}
                    disabled={awsAccountId.length !== 12}
                    className="action-box action-box-ghost flex w-full items-center justify-center gap-2 px-4 py-3 text-sm font-semibold text-slate-200 disabled:opacity-30"
                  >
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    Download JSON
                  </button>
                  <button
                    type="button"
                    onClick={handleAwsOpenConsole}
                    className="action-box action-box-cyan flex w-full items-center justify-center gap-2 px-4 py-3 text-sm font-semibold text-white"
                  >
                    Open AWS Console
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                  </button>
                </div>
                <p className="text-[0.65rem] text-slate-500">External ID: <code className="rounded bg-white/5 px-1.5 py-0.5 text-slate-400">{awsExternalId}</code></p>
              </div>

              {/* Step B: Paste Role ARN */}
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 space-y-3">
                <div className="flex items-start gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--accent-gold)]/40 bg-[var(--accent-gold)]/10 text-xs font-bold text-[var(--accent-gold)]">B</span>
                  <div>
                    <p className="text-sm font-semibold text-white">Paste the Role ARN</p>
                    <p className="mt-1 text-xs text-slate-400">After the stack completes, copy the <strong>RoleArn</strong> from the Outputs tab.</p>
                  </div>
                </div>
                <input
                  type="text"
                  value={awsRoleArn}
                  onChange={(e) => setAwsRoleArn(e.target.value)}
                  placeholder="arn:aws:iam::123456789012:role/AuthMap-Scanner-xxxxxxxx"
                  className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                />
              </div>

              {/* Region + Cost Region */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">AWS Region</label>
                  <select
                    value={awsRegion}
                    onChange={(e) => setAwsRegion(e.target.value)}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-[var(--accent-cyan)]/40"
                  >
                    {AWS_REGIONS.map((r) => (
                      <option key={r.value} value={r.value}>{r.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Cost Estimation Region</label>
                  <select
                    value={costRegion}
                    onChange={(e) => setCostRegion(e.target.value)}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-[var(--accent-cyan)]/40"
                  >
                    {COST_REGIONS.map((r) => (
                      <option key={r.value} value={r.value}>{r.label}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* ═══════════ GCP CREDENTIALS ═══════════ */}
          {step === "credentials" && provider === "gcp" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 2 — GCP</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Service Account Setup</h2>
                <p className="mt-2 text-sm text-slate-300">Provide a Service Account JSON key to grant secure, read-only scanning access to your Google Cloud Project.</p>
              </div>

              {/* Service Account Setup Guide */}
              <div className="rounded-xl border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/5 p-5 space-y-4 text-sm text-slate-300">
                <div className="flex items-center gap-3 border-b border-[var(--accent-cyan)]/20 pb-4">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--accent-cyan)]/40 bg-[var(--accent-cyan)]/10 text-xs font-bold text-[var(--accent-cyan)]">!</span>
                  <p className="text-sm font-semibold text-white">How to create the Service Account</p>
                </div>
                <ol className="ml-4 list-decimal space-y-2 text-slate-400 marker:text-slate-500">
                  <li>Go to the <a href="https://console.cloud.google.com/iam-admin/serviceaccounts" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-cyan)] hover:underline">GCP Service Accounts Console</a>.</li>
                  <li>Click <strong>+ Create Service Account</strong>, and give it a name like <code className="text-white">authmap-scanner</code>.</li>
                  <li>In the &quot;Grant this service account access&quot; step, you must grant it the 9 specific IAM Roles. You can download the JSON list of these roles below for reference.</li>
                  <li>Click Done. Click on your newly created Service Account email.</li>
                  <li>Go to the <strong>Keys</strong> tab &rarr; <strong>Add Key</strong> &rarr; <strong>Create new key</strong> &rarr; <strong>JSON</strong>.</li>
                  <li>Open the downloaded <code className="text-white">.json</code> file, copy its entire contents, and paste it below.</li>
                </ol>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={handleGcpDownloadRoles}
                    className="action-box action-box-ghost flex w-full sm:w-auto items-center justify-center gap-2 px-4 py-3 text-sm font-semibold text-slate-200"
                  >
                    <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    Download Required Roles JSON
                  </button>
                </div>
                
                <div className="mt-4 pt-4 border-t border-[var(--accent-cyan)]/20">
                  <p className="text-sm font-semibold text-white mb-2">Automate Binding via Cloud Shell</p>
                  <p className="text-xs text-slate-400 mb-2">After downloading the JSON and uploading it to your Cloud Shell, you can quickly bind all roles by running this command (replace placeholders):</p>
                  <div className="bg-black/50 p-3 rounded-lg overflow-x-auto border border-white/5">
                    <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap">
{`ROLES=$(cat authmap-gcp-roles.json | jq -r '.required_roles[]')
for role in $ROLES; do
  gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \\
    --member="serviceAccount:YOUR_SA_EMAIL" \\
    --role="$role"
done`}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Project ID */}
              <div>
                <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">GCP Project ID</label>
                <input
                  type="text"
                  value={gcpProjectId}
                  onChange={(e) => setGcpProjectId(e.target.value)}
                  placeholder="my-gcp-project-123456"
                  className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                />
              </div>

              {/* Service Account JSON Textarea */}
              <div>
                <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Service Account JSON Key</label>
                <textarea
                  value={gcpSaJson}
                  onChange={(e) => setGcpSaJson(e.target.value)}
                  placeholder='{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "client_email": "...",
  "client_id": "..."
}'
                  rows={8}
                  className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm font-mono text-white outline-none placeholder:text-slate-600 focus:border-[var(--accent-cyan)]/40"
                />
              </div>

              {/* Cost Estimation Region */}
              <div>
                <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Cost Estimation Region</label>
                <select
                  value={costRegion}
                  onChange={(e) => setCostRegion(e.target.value)}
                  className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-[var(--accent-gold)]/40"
                >
                  {COST_REGIONS.map((r) => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>
                <p className="mt-1.5 text-xs text-slate-500">Used for breach cost estimation and regulatory penalty calculations</p>
              </div>
            </div>
          )}

          {step === "scope" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 3</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Configure Scope</h2>
              </div>

              {/* Annual Revenue */}
              <div>
                <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Annual Revenue (USD)</label>
                <input
                  type="number"
                  value={annualRevenue}
                  onChange={(e) => setAnnualRevenue(e.target.value)}
                  placeholder="e.g. 5000000"
                  className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                />
                <p className="mt-1.5 text-xs text-slate-500">Optional — used for SOC2/GDPR penalty calculations</p>
              </div>

              {/* Compliance Frameworks */}
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                  Select compliance frameworks
                </p>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {COMPLIANCE_FRAMEWORKS.map((fw) => {
                    const isSelected = compliances.includes(fw.value);
                    return (
                      <button
                        key={fw.value}
                        type="button"
                        onClick={() => toggleCompliance(fw.value)}
                        className={`rounded-[1rem] border px-3 py-2.5 text-center text-sm font-medium transition ${
                          isSelected
                            ? "border-[var(--accent-cyan)]/50 bg-[rgba(158,193,182,0.12)] text-white shadow-[0_0_12px_rgba(158,193,182,0.15)]"
                            : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/18 hover:text-white"
                        }`}
                      >
                        {fw.label}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {step === "neo4j" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 4</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Database Connection</h2>
                <p className="mt-2 text-sm text-slate-400">Connect your Neo4j instance to store graph data securely.</p>
              </div>

              <div className="rounded-xl border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/5 p-4 text-sm text-slate-300">
                <p className="mb-2 font-semibold text-white">How to get these credentials:</p>
                <ol className="ml-4 list-decimal space-y-1.5 text-slate-400 marker:text-slate-500">
                  <li>Go to the <a href="https://console.neo4j.io" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-cyan)] hover:underline">Neo4j Aura Console</a>.</li>
                  <li>Create a new Free instance.</li>
                  <li><strong>Important:</strong> A <code className="rounded bg-black/40 px-1 py-0.5 text-white">.txt</code> credentials file will automatically download. Save this file!</li>
                  <li>Wait a minute or two for your instance status to show &quot;Running&quot;.</li>
                  <li>Copy the <strong>Connection URI</strong> from your Aura dashboard.</li>
                  <li>Copy the <strong>Username</strong> (usually <code className="text-white">neo4j</code>) and <strong>Password</strong> from your downloaded <code className="rounded bg-black/40 px-1 py-0.5 text-white">.txt</code> file.</li>
                </ol>
              </div>

              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-5 space-y-4">
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Neo4j URI</label>
                  <input
                    type="text"
                    placeholder="neo4j+s://..."
                    value={neo4jUri}
                    onChange={(e) => setNeo4jUri(e.target.value)}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Username</label>
                  <input
                    type="text"
                    value={neo4jUser}
                    onChange={(e) => setNeo4jUser(e.target.value)}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-[var(--accent-cyan)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Password</label>
                  <input
                    type="password"
                    value={neo4jPassword}
                    onChange={(e) => setNeo4jPassword(e.target.value)}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-[var(--accent-cyan)]/40"
                  />
                </div>
              </div>
            </div>
          )}

          {step === "launch" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 5</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Review & launch</h2>
              </div>
              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0">Provider</span>
                  <span className="text-xs sm:text-sm font-semibold text-white uppercase break-all sm:text-right">{provider}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0">Auth Method</span>
                  <span className="text-xs sm:text-sm font-semibold text-green-400 break-words sm:text-right">
                    {provider === "aws" ? "STS Cross-Account Role ✓" : "Google SA Key ✓"}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0">Neo4j Database</span>
                  <span className="text-xs sm:text-sm font-semibold text-green-400 break-words sm:text-right">
                    {neo4jUri ? `${neo4jUri} ✓` : "Localhost"}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0">Cost Region</span>
                  <span className="text-xs sm:text-sm font-semibold text-white sm:text-right">
                    {COST_REGIONS.find((r) => r.value === costRegion)?.label ?? costRegion}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0">Annual Revenue</span>
                  <span className="text-xs sm:text-sm font-semibold text-white sm:text-right">
                    {annualRevenue ? `$${parseFloat(annualRevenue).toLocaleString()}` : "$0 (Not provided)"}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1.5 sm:gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 min-w-0">
                  <span className="text-xs font-medium text-slate-400 shrink-0 pt-0.5">Compliances</span>
                  <span className="text-xs sm:text-sm font-semibold text-white break-words sm:text-right min-w-0 leading-relaxed">
                    {compliances.length > 0
                      ? compliances.map((c) => COMPLIANCE_FRAMEWORKS.find((f) => f.value === c)?.label ?? c).join(", ")
                      : "None selected"}
                  </span>
                </div>
              </div>

              {/* Scan progress section */}
              {scanStatus && (
                <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.03] p-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 min-w-0">
                    <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] font-medium uppercase tracking-[0.2em] text-slate-400 shrink-0">
                      Scan Progress
                    </p>
                    <span className="text-[0.7rem] font-mono text-slate-500 break-all">ID #{scanStatus.scan_id}</span>
                  </div>

                  {/* Progress bar */}
                  <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/[0.06]">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        scanStatus.status === "failed"
                          ? "bg-red-500"
                          : scanStatus.status === "completed"
                          ? "bg-green-500"
                          : "bg-[var(--accent-cyan)]"
                      }`}
                      style={{ width: `${getProgressPercent(scanStatus.status, scanStatus.progress)}%` }}
                    />
                  </div>

                  {/* Phase text */}
                  <div className="flex items-center justify-between">
                    <p className={`text-sm font-medium ${
                      scanStatus.status === "failed" ? "text-red-400" : scanStatus.status === "completed" ? "text-green-400" : "text-white"
                    }`}>
                      {getPhaseLabel(scanStatus.status)}
                    </p>
                    <span className="text-sm font-semibold text-slate-400">
                      {getProgressPercent(scanStatus.status, scanStatus.progress)}%
                    </span>
                  </div>

                  {/* Error message */}
                  {scanStatus.status === "failed" && scanStatus.error && (
                    <p className="text-sm text-red-400">{scanStatus.error}</p>
                  )}

                  {/* Completion links */}
                  {scanStatus.status === "completed" && (
                    <div className="space-y-3.5 border-t border-white/10 pt-4">
                      <p className="text-sm font-medium text-green-400">
                        ✓ Analysis completed successfully
                      </p>

                      {/* Prominent Ask AI (Full Screen) Option */}
                      <Link
                        href="/ask"
                        className="action-box action-box-cyan flex w-full items-center justify-center gap-2 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-500/10 hover:shadow-cyan-500/20"
                      >
                        <svg className="h-4 w-4 text-[var(--accent-cyan)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M12 2a8 8 0 0 0-8 8c0 3.37 2.07 6.27 5 7.46V20a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2.54c2.93-1.19 5-4.09 5-7.46a8 8 0 0 0-8-8z"/>
                          <line x1="9.5" y1="9" x2="9.51" y2="9"/>
                          <line x1="14.5" y1="9" x2="14.51" y2="9"/>
                        </svg>
                        <span>Ask AuthMap AI (Full Screen) →</span>
                      </Link>

                      {/* Secondary Exploration Links */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                        <Link
                          href="/graph"
                          className="action-box action-box-ghost flex items-center justify-center px-3.5 py-2.5 text-xs font-medium text-slate-200 hover:text-white"
                        >
                          View Graph →
                        </Link>
                        <Link
                          href="/findings"
                          className="action-box action-box-magenta flex items-center justify-center px-3.5 py-2.5 text-xs font-medium text-slate-200 hover:text-white"
                        >
                          View Findings →
                        </Link>
                        <Link
                          href="/cost-matrix"
                          className="action-box action-box-gold flex items-center justify-center px-3.5 py-2.5 text-xs font-medium text-slate-200 hover:text-white"
                        >
                          Cost Matrix →
                        </Link>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {launchResult && !scanStatus && (
                <p className={`text-sm ${launchResult.includes("success") ? "text-green-400" : "text-red-400"}`}>
                  {launchResult}
                </p>
              )}

              {!scanStatus && (
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setScanStatus(null);
                      setStep("provider");
                    }}
                    disabled={isLaunching}
                    className="action-box action-box-ghost w-1/3 px-5 py-3.5 disabled:opacity-50 mt-2 text-sm font-semibold text-white"
                  >
                    Rescan
                  </button>
                  <button
                    type="button"
                    onClick={handleLaunch}
                    disabled={isLaunching}
                    className="action-box action-box-cyan flex w-2/3 items-center justify-center gap-2 px-5 py-3.5 disabled:opacity-50 mt-2 text-sm font-semibold text-white"
                  >
                    {isLaunching && (
                      <svg className="h-4 w-4 animate-spin text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                    )}
                    {isLaunching ? "Launching..." : "Launch Analysis"}
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Validation Error */}
          {verifyError && (
            <div className="mt-4 rounded-xl bg-red-500/10 px-4 py-3 border border-red-500/20">
              <p className="text-sm font-medium text-red-400">{verifyError}</p>
            </div>
          )}

          {/* Navigation buttons */}
          <div className="mt-6 flex items-center justify-between border-t border-white/10 pt-5">
            <button
              type="button"
              onClick={goBack}
              disabled={currentStepIndex === 0}
              className="action-box action-box-ghost px-4 py-2.5 text-sm font-medium text-white disabled:opacity-30"
            >
              ← Back
            </button>
            {step !== "launch" && (
              <button
                type="button"
                onClick={goNext}
                disabled={!canProceed() || isVerifying}
                className="action-box action-box-cyan px-5 py-2.5 text-sm font-semibold text-white disabled:opacity-40"
              >
                {isVerifying ? "Verifying..." : "Continue"}
              </button>
            )}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
