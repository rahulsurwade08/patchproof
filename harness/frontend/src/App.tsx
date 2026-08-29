import {
  TrueForgeUI,
  WelcomeScreen,
  type AtomSlots,
  type ThemeConfig,
} from "@truefoundry/trueforge-ui";

const patchproofTheme: ThemeConfig = {
  preset: "trueforge",
  mode: "dark",
  brand: {
    name: "PatchProof",
    logo: "/patchproof-mark.svg",
    href: "/",
  },
  tokens: {
    primaryBg: "#0b1220",
    secondaryBg: "#0f1a2e",
    sidebarBg: "#08111e",
    topbarBg: "#0a1322",
    cardBg: "#0f1a2e",
    border: "#1f2d44",
    textPrimary: "#e6edf7",
    textSecondary: "#9ba8be",
    inputBoxBg: "#0a1322",
    inputBorder: "#22314a",
    userMessageBg: "#1b3a5e",
    userMessageText: "#e6edf7",
    assistantMessageBg: "#0f1a2e",
    assistantMessageText: "#e6edf7",
    primaryButtonBg: "#3b82f6",
    primaryButtonHover: "#2563eb",
    primaryButtonText: "#ffffff",
    successBg: "#14532d",
    successText: "#86efac",
    failureBg: "#7f1d1d",
    failureText: "#fecaca",
  },
};

const patchproofOverrides: Partial<AtomSlots> = {
  BrandLogo: () => (
    <span className="flex items-center gap-2">
      <span
        aria-hidden
        className="inline-block h-6 w-6 rounded-md"
        style={{
          background:
            "linear-gradient(135deg, #ef4444 0%, #f59e0b 50%, #10b981 100%)",
        }}
      />
      <span className="font-semibold tracking-tight text-[15px] text-white">
        PatchProof
      </span>
    </span>
  ),
  WelcomeScreen: () => (
    <div className="flex h-full w-full items-center justify-center px-6">
      <div className="max-w-2xl w-full text-center">
        <h1 className="text-3xl font-semibold text-white mb-2">
          PatchProof
        </h1>
        <p className="text-sm text-slate-300 mb-6">
          Reachability triage + sandbox-confirmed exploits + auto-patches.
          Each CVE gets one session; the agent pauses for human approval
          before any deploy.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left">
          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
            <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
              1 · Triage
            </div>
            <div className="text-sm text-slate-100">Reachability</div>
            <div className="text-xs text-slate-400 mt-1">
              dep-pin + call-site + input trace
            </div>
          </div>
          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
            <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
              2 · Confirm
            </div>
            <div className="text-sm text-slate-100">Exploit</div>
            <div className="text-xs text-slate-400 mt-1">
              sandbox: <code>--network none</code>, no host fallbacks
            </div>
          </div>
          <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
            <div className="text-xs uppercase tracking-wide text-slate-400 mb-1">
              3 · Patch
            </div>
            <div className="text-sm text-slate-100">+ Verify</div>
            <div className="text-xs text-slate-400 mt-1">
              human-approved merge + staging
            </div>
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-6">
          Drop a CVE id or paste an advisory JSON in the composer below.
        </p>
      </div>
    </div>
  ),
};

export default function App() {
  return (
    <div className="h-screen w-screen">
      <TrueForgeUI
        server={{ type: "trueforge", baseUrl: "/api" }}
        agentConfig={{ mode: "SingleAgent", name: "patchproof-v2" }}
        theme={patchproofTheme}
        overrides={patchproofOverrides}
        layout="sidebar"
      />
    </div>
  );
}
