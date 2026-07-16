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
  const [awsAccessKeyId, setAwsAccessKeyId] = useState("");
  const [awsSecretKey, setAwsSecretKey] = useState("");
  const [awsRegion, setAwsRegion] = useState("us-east-1");
  const [gcpProjectId, setGcpProjectId] = useState("");
  const [gcpServiceAccountKey, setGcpServiceAccountKey] = useState("");
  const [neo4jUri, setNeo4jUri] = useState("");
  const [neo4jUsername, setNeo4jUsername] = useState("");
  const [neo4jPassword, setNeo4jPassword] = useState("");
  const [neo4jProjectId, setNeo4jProjectId] = useState("");
  const [isLaunching, setIsLaunching] = useState(false);
  const [launchResult, setLaunchResult] = useState<string | null>(null);

  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  // New state for added fields
  const [costRegion, setCostRegion] = useState("INDIA");
  const [annualRevenue, setAnnualRevenue] = useState("");
  const [compliances, setCompliances] = useState<string[]>(["SOC2", "DPDP"]);

  // Scan progress polling state
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const steps: { id: WizardStep; label: string; num: string }[] = [
    { id: "provider", label: "Provider", num: "1" },
    { id: "credentials", label: "Credentials", num: "2" },
    { id: "scope", label: "Scope", num: "3" },
    { id: "neo4j", label: "Neo4j", num: "4" },
    { id: "launch", label: "Launch", num: "5" },
  ];

  const currentStepIndex = steps.findIndex((s) => s.id === step);

  // Clean up polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, []);

  // Hydrate credentials from sessionStorage on mount
  useEffect(() => {
    const saved = sessionStorage.getItem('boxai_scan_creds');
    if (saved) {
      try {
        const data = JSON.parse(saved);
        if (data.provider) setProvider(data.provider);
        if (data.awsAccessKeyId) setAwsAccessKeyId(data.awsAccessKeyId);
        if (data.awsSecretKey) setAwsSecretKey(data.awsSecretKey);
        if (data.awsRegion) setAwsRegion(data.awsRegion);
        if (data.gcpProjectId) setGcpProjectId(data.gcpProjectId);
        if (data.gcpServiceAccountKey) setGcpServiceAccountKey(data.gcpServiceAccountKey);
        if (data.neo4jUri) setNeo4jUri(data.neo4jUri);
        if (data.neo4jUsername) setNeo4jUsername(data.neo4jUsername);
        if (data.neo4jPassword) setNeo4jPassword(data.neo4jPassword);
        if (data.neo4jProjectId) setNeo4jProjectId(data.neo4jProjectId);
        if (data.costRegion) setCostRegion(data.costRegion);
        if (data.annualRevenue) setAnnualRevenue(data.annualRevenue);
        if (data.compliances) setCompliances(data.compliances);
      } catch (e) {}
    }
  }, []);

  // Save credentials to sessionStorage whenever they change
  useEffect(() => {
    const creds = {
      provider, awsAccessKeyId, awsSecretKey, awsRegion, gcpProjectId, gcpServiceAccountKey,
      neo4jUri, neo4jUsername, neo4jPassword, neo4jProjectId, costRegion, annualRevenue, compliances
    };
    sessionStorage.setItem('boxai_scan_creds', JSON.stringify(creds));
  }, [provider, awsAccessKeyId, awsSecretKey, awsRegion, gcpProjectId, gcpServiceAccountKey, neo4jUri, neo4jUsername, neo4jPassword, neo4jProjectId, costRegion, annualRevenue, compliances]);

  const startPolling = useCallback(
    (scanId: number) => {
      setIsPolling(true);
      const poll = async () => {
        try {
          const token = await getToken();
          const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
          const res = await fetch(`${backendUrl}/scan/status/${scanId}`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (res.ok) {
            const data: ScanStatus = await res.json();
            setScanStatus(data);
            if (data.status === "completed" || data.status === "failed") {
              if (pollingRef.current) clearInterval(pollingRef.current);
              setIsPolling(false);
            }
          }
        } catch {
          // Polling error — keep trying
        }
      };
      poll();
      pollingRef.current = setInterval(poll, 2000);
    },
    [getToken]
  );

  function toggleCompliance(value: string) {
    setCompliances((prev) =>
      prev.includes(value) ? prev.filter((c) => c !== value) : [...prev, value]
    );
  }

  function canProceed(): boolean {
    if (step === "provider") return true;
    if (step === "credentials") {
      if (provider === "aws") return awsAccessKeyId.trim().length > 0 && awsSecretKey.trim().length > 0;
      return gcpProjectId.trim().length > 0 && gcpServiceAccountKey.trim().length > 0;
    }
    if (step === "scope") return true;
    if (step === "neo4j") return true;
    return false;
  }

  async function goNext() {
    if (step === "credentials") {
      if (provider === "aws" && !awsAccessKeyId.trim().startsWith("AKIA") && !awsAccessKeyId.trim().startsWith("ASIA")) {
         setVerifyError("Invalid AWS Access Key format. Must start with AKIA or ASIA.");
         return;
      }
      if (provider === "gcp") {
         try {
           const parsed = JSON.parse(gcpServiceAccountKey);
           if (!parsed.private_key || !parsed.client_email) {
             setVerifyError("Invalid GCP JSON. Must contain private_key and client_email.");
             return;
           }
         } catch {
           setVerifyError("Invalid GCP JSON format. Please paste a valid JSON object.");
           return;
         }
      }

      setIsVerifying(true);
      setVerifyError(null);
      try {
        const token = await getToken();
        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
        const body = provider === "aws" 
          ? { provider: "aws", aws_access_key_id: awsAccessKeyId.trim(), aws_secret_key: awsSecretKey.trim(), region: awsRegion }
          : { provider: "gcp", gcp_project_id: gcpProjectId.trim(), gcp_service_account_key: gcpServiceAccountKey.trim() };
          
        const res = await fetch(`${backendUrl}/scan/verify-credentials`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!data.valid && data.error && !data.error.includes("Neo4j")) {
          setVerifyError(data.error || "Connection test failed.");
          setIsVerifying(false);
          return;
        }
      } catch (e) {
        setVerifyError("Could not reach backend to verify credentials.");
        setIsVerifying(false);
        return;
      }
      setIsVerifying(false);
    }

    if (step === "neo4j" && neo4jUri.trim()) {
      setIsVerifying(true);
      setVerifyError(null);
      try {
        const token = await getToken();
        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
        const res = await fetch(`${backendUrl}/scan/verify-credentials`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ 
            provider: provider,
            neo4j_uri: neo4jUri.trim(), 
            neo4j_username: neo4jUsername.trim(), 
            neo4j_password: neo4jPassword.trim() 
          })
        });
        const data = await res.json();
        if (!data.valid && data.error && data.error.includes("Neo4j")) {
          setVerifyError(data.error);
          setIsVerifying(false);
          return;
        }
      } catch {
        setVerifyError("Could not reach backend to verify Neo4j connection.");
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

  async function handleLaunch() {
    setIsLaunching(true);
    setLaunchResult(null);
    setScanStatus(null);
    try {
      const token = await getToken();
      const neo4jCreds = neo4jUri.trim()
        ? { neo4j_uri: neo4jUri.trim(), neo4j_username: neo4jUsername.trim(), neo4j_password: neo4jPassword.trim(), neo4j_project_id: neo4jProjectId.trim() }
        : {};

      const baseBody = provider === "aws"
        ? { provider: "aws", aws_access_key_id: awsAccessKeyId.trim(), aws_secret_key: awsSecretKey.trim(), region: awsRegion, ...neo4jCreds }
        : { provider: "gcp", gcp_project_id: gcpProjectId.trim(), gcp_service_account_key: gcpServiceAccountKey.trim(), ...neo4jCreds };

      const accountName = user?.fullName || user?.firstName || user?.username || user?.primaryEmailAddress?.emailAddress?.split("@")[0] || "Operator";
      
      const body = {
        ...baseBody,
        cost_region: costRegion,
        annual_revenue: annualRevenue ? parseFloat(annualRevenue) : null,
        selected_compliances: compliances,
        account_name: accountName
      };

      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      const res = await fetch(`${backendUrl}/scan/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.scan_id) {
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
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Scan Wizard"
          title="Connect. Configure. Launch."
          description="Four steps to a full IAM attack path analysis across your cloud environment."
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

          {step === "credentials" && provider === "aws" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 2 — AWS</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Enter AWS credentials</h2>
                <p className="mt-2 text-sm text-slate-300">Read-only IAM access is sufficient. Keys are held in memory only.</p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Access Key ID</label>
                  <input
                    type="text"
                    value={awsAccessKeyId}
                    onChange={(e) => setAwsAccessKeyId(e.target.value)}
                    placeholder="AKIAIOSFODNN7EXAMPLE"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Secret Access Key</label>
                  <input
                    type="password"
                    value={awsSecretKey}
                    onChange={(e) => setAwsSecretKey(e.target.value)}
                    placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-cyan)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Region</label>
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
                {/* Cost Estimation Region */}
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
                  <p className="mt-1.5 text-xs text-slate-500">Used for breach cost estimation and regulatory penalty calculations</p>
                </div>
              </div>
            </div>
          )}

          {step === "credentials" && provider === "gcp" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 2 — GCP</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Enter GCP credentials</h2>
                <p className="mt-2 text-sm text-slate-300">Viewer-level IAM access is sufficient. Keys are held in memory only.</p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Project ID</label>
                  <input
                    type="text"
                    value={gcpProjectId}
                    onChange={(e) => setGcpProjectId(e.target.value)}
                    placeholder="my-gcp-project-123"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Service Account Key (JSON)</label>
                  <textarea
                    value={gcpServiceAccountKey}
                    onChange={(e) => setGcpServiceAccountKey(e.target.value)}
                    placeholder={'{\n  "type": "service_account",\n  "project_id": "my-project",\n  ...\n}'}
                    rows={6}
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
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
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 4 — Optional</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Neo4j Aura Cloud</h2>
                <p className="mt-2 text-sm text-slate-300">Connect a Neo4j Aura instance to persist your IAM graph. This is optional — skip if you don&apos;t have one.</p>
              </div>
              <div className="space-y-4">
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Aura Connection URI</label>
                  <input
                    type="text"
                    value={neo4jUri}
                    onChange={(e) => setNeo4jUri(e.target.value)}
                    placeholder="neo4j+s://xxxxxxxx.databases.neo4j.io"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Username</label>
                  <input
                    type="text"
                    value={neo4jUsername}
                    onChange={(e) => setNeo4jUsername(e.target.value)}
                    placeholder="neo4j"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Password</label>
                  <input
                    type="password"
                    value={neo4jPassword}
                    onChange={(e) => setNeo4jPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
                  />
                </div>
                <div>
                  <label className="text-[0.65rem] font-medium uppercase tracking-widest text-slate-400">Project ID</label>
                  <input
                    type="text"
                    value={neo4jProjectId}
                    onChange={(e) => setNeo4jProjectId(e.target.value)}
                    placeholder="aura-project-id"
                    className="mt-1.5 w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none placeholder:text-slate-500 focus:border-[var(--accent-gold)]/40"
                  />
                </div>
              </div>
              <button
                type="button"
                onClick={goNext}
                className="action-box action-box-ghost w-full px-4 py-2.5 text-sm font-medium text-slate-300"
              >
                Skip — I don&apos;t have Neo4j Aura →
              </button>
            </div>
          )}

          {step === "launch" && (
            <div className="space-y-5">
              <div>
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">Step 5</p>
                <h2 className="mt-2 text-2xl font-semibold text-white">Review & launch</h2>
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Provider</span>
                  <span className="text-sm font-semibold text-white uppercase">{provider}</span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Scope</span>
                  <span className="text-sm font-semibold text-white">Full IAM Graph</span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Credentials</span>
                  <span className="text-sm font-semibold text-green-400">Provided ✓</span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Neo4j Aura</span>
                  <span className={`text-sm font-semibold ${neo4jUri.trim() ? "text-green-400" : "text-slate-500"}`}>
                    {neo4jUri.trim() ? "Connected ✓" : "Skipped"}
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Cost Region</span>
                  <span className="text-sm font-semibold text-white">
                    {COST_REGIONS.find((r) => r.value === costRegion)?.label ?? costRegion}
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Annual Revenue</span>
                  <span className="text-sm font-semibold text-white">
                    {annualRevenue ? `$${parseFloat(annualRevenue).toLocaleString()}` : "Not provided"}
                  </span>
                </div>
                <div className="flex items-center justify-between rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                  <span className="text-sm text-slate-400">Compliances</span>
                  <span className="text-sm font-semibold text-white">
                    {compliances.length > 0
                      ? compliances.map((c) => COMPLIANCE_FRAMEWORKS.find((f) => f.value === c)?.label ?? c).join(", ")
                      : "None selected"}
                  </span>
                </div>
              </div>

              {/* Scan progress section */}
              {scanStatus && (
                <div className="space-y-4 rounded-xl border border-white/10 bg-white/[0.03] p-5">
                  <div className="flex items-center justify-between">
                    <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] font-medium uppercase tracking-[0.2em] text-slate-400">
                      Scan Progress
                    </p>
                    <span className="text-xs text-slate-500">ID #{scanStatus.scan_id}</span>
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
                    <div className="space-y-3 border-t border-white/10 pt-4">
                      <p className="text-sm font-medium text-green-400">
                        ✓ Analysis completed successfully
                      </p>
                      <div className="flex flex-wrap gap-2">
                        <Link
                          href="/graph"
                          className="action-box action-box-cyan px-4 py-2 text-xs font-semibold text-white"
                        >
                          View Graph →
                        </Link>
                        <Link
                          href="/findings"
                          className="action-box action-box-magenta px-4 py-2 text-xs font-semibold text-white"
                        >
                          View Findings →
                        </Link>
                        <Link
                          href="/cost-matrix"
                          className="action-box action-box-gold px-4 py-2 text-xs font-semibold text-white"
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
                    className="action-box action-box-ghost w-1/3 px-5 py-3.5 text-sm font-semibold uppercase tracking-[0.18em] text-slate-300 disabled:opacity-50"
                  >
                    Rescan
                  </button>
                  <button
                    type="button"
                    onClick={handleLaunch}
                    disabled={isLaunching}
                    className="action-box action-box-cyan flex w-2/3 items-center justify-center gap-2 px-5 py-3.5 text-sm font-semibold uppercase tracking-[0.18em] text-white disabled:opacity-50"
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
