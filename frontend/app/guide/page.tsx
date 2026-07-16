"use client";

import { useState } from "react";
import { AppShell } from "@/components/app-shell";
import { GooeyTabs, TabItem } from "@/components/gooey-tabs";
import { ChevronRight, Server, Shield, Network } from "lucide-react";
import Link from "next/link";

export default function GuidePage() {
  const [activeTab, setActiveTab] = useState<"aws" | "gcp" | "neo4j">("aws");

  return (
    <AppShell>
      <div className="mx-auto max-w-5xl py-8 px-4 sm:px-6">
        <div className="mb-8 flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">Integration Guide</h1>
            <p className="mt-2 text-slate-400">
              Configure your cloud environments and graph database to allow AuthMap to securely analyze your IAM attack surface.
            </p>
          </div>
          <Link href="/">
            <button className="action-box action-box-cyan flex items-center justify-center gap-2 px-6 py-3 text-sm font-semibold uppercase tracking-wider text-white">
              Continue to Dashboard <ChevronRight className="h-4 w-4" />
            </button>
          </Link>
        </div>

        <div className="mb-8 w-full md:max-w-[34rem] lg:max-w-[40rem] mx-auto">
          <GooeyTabs 
            items={[
              { id: "aws", label: "Amazon Web Services" },
              { id: "gcp", label: "Google Cloud Platform" },
              { id: "neo4j", label: "Neo4j Aura" }
            ]}
            activeTab={activeTab}
            onChange={(id) => setActiveTab(id as any)}
          />
        </div>

        <div className="rounded-2xl border border-white/10 bg-[#0a0d12]/50 p-6 md:p-8">
          {activeTab === "aws" && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="text-2xl font-semibold text-white flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-cyan)]/20 text-[var(--accent-cyan)]">
                  1
                </div>
                AWS Setup Instructions
              </h2>
              <p className="text-slate-300">
                AuthMap requires a dedicated IAM Role or User with Read-Only permissions to safely scan your AWS environment without the ability to modify resources.
              </p>

              <div className="space-y-4">
                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">1. Create an IAM User</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>Log into your AWS Management Console.</li>
                    <li>Navigate to <strong>IAM &gt; Users &gt; Add users</strong>.</li>
                    <li>Name the user <code className="bg-black/30 px-1.5 py-0.5 rounded text-cyan-400">authmap-scanner</code>.</li>
                    <li>Select <strong>Attach policies directly</strong>.</li>
                  </ol>
                </div>

                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">2. Attach Required Policies</h3>
                  <p className="text-sm text-slate-400 mb-3">Search for and check the following AWS managed policies:</p>
                  <ul className="list-disc list-inside space-y-2 text-sm text-slate-300">
                    <li><code className="bg-black/30 px-1.5 py-0.5 rounded text-cyan-400">SecurityAudit</code></li>
                    <li><code className="bg-black/30 px-1.5 py-0.5 rounded text-cyan-400">ReadOnlyAccess</code></li>
                  </ul>
                </div>

                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">3. Generate Access Keys</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>Once the user is created, click on the user name.</li>
                    <li>Go to the <strong>Security credentials</strong> tab.</li>
                    <li>Click <strong>Create access key</strong>.</li>
                    <li>Select <strong>Third-party service</strong> as the use case.</li>
                    <li>Copy the <strong>Access Key ID</strong> and <strong>Secret Access Key</strong>. You will need these when starting a scan!</li>
                  </ol>
                </div>
              </div>
            </div>
          )}

          {activeTab === "gcp" && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="text-2xl font-semibold text-white flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-magenta)]/20 text-[var(--accent-magenta)]">
                  2
                </div>
                GCP Setup Instructions
              </h2>
              <p className="text-slate-300">
                AuthMap requires a Google Cloud Service Account to fetch IAM policies, Asset Inventory, and organization metadata.
              </p>

              <div className="space-y-4">
                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">1. Create a Service Account</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>Log into your Google Cloud Console.</li>
                    <li>Navigate to <strong>IAM &amp; Admin &gt; Service Accounts</strong>.</li>
                    <li>Click <strong>+ CREATE SERVICE ACCOUNT</strong>.</li>
                    <li>Name it <code className="bg-black/30 px-1.5 py-0.5 rounded text-magenta-400">authmap-scanner</code> and click Create and Continue.</li>
                  </ol>
                </div>

                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">2. Assign Roles</h3>
                  <p className="text-sm text-slate-400 mb-3">Assign the following roles to the service account:</p>
                  <ul className="list-disc list-inside space-y-2 text-sm text-slate-300">
                    <li><code className="bg-black/30 px-1.5 py-0.5 rounded text-magenta-400">Viewer</code> (Basic read-only access)</li>
                    <li><code className="bg-black/30 px-1.5 py-0.5 rounded text-magenta-400">Security Reviewer</code> (Allows reading IAM policies and Cloud Asset Inventory)</li>
                  </ul>
                </div>

                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">3. Generate JSON Key</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>Click on the newly created Service Account.</li>
                    <li>Go to the <strong>KEYS</strong> tab.</li>
                    <li>Click <strong>ADD KEY &gt; Create new key</strong>.</li>
                    <li>Select <strong>JSON</strong> and click Create.</li>
                    <li>A `.json` file will download to your computer. You will copy and paste the entire contents of this file into AuthMap when launching a scan.</li>
                  </ol>
                </div>
                
                <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-5">
                  <h3 className="text-sm font-medium text-yellow-500 mb-2">Required APIs</h3>
                  <p className="text-xs text-yellow-500/80">Make sure the following APIs are enabled in your GCP project: <strong>Cloud Asset API</strong>, <strong>IAM API</strong>, and <strong>Cloud Resource Manager API</strong>.</p>
                </div>
              </div>
            </div>
          )}

          {activeTab === "neo4j" && (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
              <h2 className="text-2xl font-semibold text-white flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-gold)]/20 text-[var(--accent-gold)]">
                  3
                </div>
                Neo4j Aura Setup
              </h2>
              <p className="text-slate-300">
                AuthMap uses Neo4j to store and traverse your cloud identity graph. You can create a free cloud database on Neo4j Aura.
              </p>

              <div className="space-y-4">
                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">1. Create a Database</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>Go to <a href="https://console.neo4j.io/" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-gold)] hover:underline">console.neo4j.io</a> and log in.</li>
                    <li>Click <strong>New Instance</strong> and select the <strong>AuraDB Free</strong> tier.</li>
                    <li>Once the database is created, you will be shown a modal containing your <strong>Username</strong> (usually <code className="bg-black/30 px-1 py-0.5 rounded text-white">neo4j</code>) and a generated <strong>Password</strong>.</li>
                    <li><strong className="text-red-400">Save this password immediately!</strong> You cannot see it again.</li>
                  </ol>
                </div>

                <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
                  <h3 className="text-lg font-medium text-white mb-3">2. Get your Connection URI</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                    <li>On the Neo4j Aura dashboard, locate your running instance.</li>
                    <li>Look for the <strong>Connection URI</strong>. It will look something like this:</li>
                  </ol>
                  <div className="mt-3 flex items-center justify-between rounded-lg bg-black/40 p-3 font-mono text-xs text-slate-400">
                    <span>neo4j+s://&lt;your-project-id&gt;.databases.neo4j.io</span>
                  </div>
                </div>

                <div className="rounded-xl border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/5 p-5">
                  <h3 className="text-sm font-medium text-[var(--accent-cyan)] mb-2">How AuthMap uses this</h3>
                  <p className="text-xs text-[var(--accent-cyan)]/80">
                    During the scan wizard, you will input your URI, username, and password. AuthMap will stream the IAM attack paths directly into your Neo4j instance, where they are mathematically scored for blast radius.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
