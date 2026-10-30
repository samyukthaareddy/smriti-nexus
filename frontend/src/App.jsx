import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  BookOpen,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  Download,
  FileText,
  GitBranch,
  History,
  Layers,
  MessageSquare,
  Plus,
  RefreshCw,
  Search,
  Shield,
  X,
  GitPullRequest,
  ExternalLink,
  LockKeyhole,
} from "lucide-react";
import { ReactFlow, Background, Controls, MiniMap } from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const API = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "http://localhost:8001" : "");
const DEMO_MODE = import.meta.env.DEV && import.meta.env.VITE_DEMO_MODE !== "false";
let accessToken = window.sessionStorage.getItem("smriti_access_token") || "";

function saveAccessToken(token) {
  accessToken = token || "";
  if (accessToken) window.sessionStorage.setItem("smriti_access_token", accessToken);
  else window.sessionStorage.removeItem("smriti_access_token");
}
const nav = [
  ["Overview", Layers],
  ["Agent Workspace", MessageSquare],
  ["Memory Explorer", BookOpen],
  ["Knowledge Graph", GitBranch],
  ["Incidents & Decisions", Activity],
  ["Knowledge Transfer", FileText],
  ["Correction Review", GitPullRequest],
  ["Security & Audit", Shield],
];
const statuses = ["Verified", "Unverified", "Disputed", "Superseded", "Archived"];
const suggestions = [
  "How did we resolve the payment timeout incident?",
  "Why did the architecture change?",
  "What remains unverified?",
];
const emptyDraft = {
  title: "",
  memory_type: "Project context",
  project: "Payment Service",
  status: "Unverified",
  content: "",
  source: "manual-entry.md",
  supersedes_id: "",
  sensitivity: "INTERNAL",
  tags: [],
};

async function api(path, options) {
  if (!API) {
    throw new Error("Set VITE_API_URL to the deployed Smriti Nexus API before building.");
  }
  let response;
  try {
    const headers = new Headers(options?.headers || {});
    if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
    response = await fetch(`${API.replace(/\/+$/, "")}${path}`, { ...options, headers });
  } catch {
    throw new Error("Could not reach the configured Smriti Nexus API.");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && accessToken) {
      saveAccessToken("");
      window.dispatchEvent(new Event("smriti:unauthorized"));
    }
    const exception = new Error(data.detail || `The API returned ${response.status}.`);
    exception.status = response.status;
    throw exception;
  }
  return data;
}

async function createInvitation(event) {
  event.preventDefault();
  setError("");
  setInvitationToken("");
  try {
    const result = await api("/api/org/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
    });
    setInvitationToken(result.invitation_token);
    setInviteEmail("");
    await loadAudit();
  } catch (exception) {
    setError(exception.message);
  }
}

async function changeMemberRole(userId, role) {
  try {
    await api(`/api/org/users/${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    await loadAudit();
  } catch (exception) {
    setError(exception.message);
  }
}

function auditExportUrl(query, action) {
  const url = new URL(`${API.replace(/\/+$/, "")}/api/audit/export`, window.location.origin);
  url.searchParams.set("q", query);
  url.searchParams.set("action", action);
  return url.toString();
}

export default function App() {
  const [authReady, setAuthReady] = useState(DEMO_MODE);
  const [authToken, setAuthToken] = useState(DEMO_MODE ? "local-demo" : accessToken);
  const [currentUser, setCurrentUser] = useState(
    DEMO_MODE ? { email: "demo@localhost", role: "admin" } : null,
  );
  const [authMode, setAuthMode] = useState("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [invitationTokenInput, setInvitationTokenInput] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [page, setPage] = useState("Landing");
  const [memories, setMemories] = useState([]);
  const [status, setStatus] = useState("All");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState(null);
  const [privacyPreview, setPrivacyPreview] = useState(null);
  const [pendingQuestion, setPendingQuestion] = useState("");
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditActions, setAuditActions] = useState([]);
  const [auditSearch, setAuditSearch] = useState("");
  const [auditAction, setAuditAction] = useState("memory");
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditExporting, setAuditExporting] = useState(false);
  const [auditNotice, setAuditNotice] = useState("");
  const [securityOverview, setSecurityOverview] = useState(null);
  const [members, setMembers] = useState([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("employee");
  const [invitationToken, setInvitationToken] = useState("");
  const [graphQuery, setGraphQuery] = useState("");
  const [corrections, setCorrections] = useState([]);
  const [correctionFilter, setCorrectionFilter] = useState("pending");
  const [correctionLoading, setCorrectionLoading] = useState(false);
  const [correctionBusy, setCorrectionBusy] = useState("");
  const [sourceDocument, setSourceDocument] = useState(null);
  const [sourceLoading, setSourceLoading] = useState(false);
  const [sourceDenied, setSourceDenied] = useState(false);
  const [memoryHistory, setMemoryHistory] = useState([]);
  const [handoverProject, setHandoverProject] = useState("");
  const [handover, setHandover] = useState(null);
  const [handoverLoading, setHandoverLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [memoryFormOpen, setMemoryFormOpen] = useState(false);
  const [editingMemoryId, setEditingMemoryId] = useState("");
  const [draft, setDraft] = useState(emptyDraft);
  const [saving, setSaving] = useState(false);
  const memoryRequest = useRef(0);
  const auditRequest = useRef(0);

  useEffect(() => {
    let active = true;
    const handleUnauthorized = () => {
      saveAccessToken("");
      setAuthToken("");
      setCurrentUser(null);
      setAuthReady(true);
      setPage("Landing");
    };
    window.addEventListener("smriti:unauthorized", handleUnauthorized);
    if (DEMO_MODE) {
      return () => window.removeEventListener("smriti:unauthorized", handleUnauthorized);
    } else if (!accessToken) {
      setAuthReady(true);
    } else {
      api("/api/auth/me")
        .then((data) => {
          if (active) {
            setCurrentUser(data.user);
            setAuthReady(true);
          }
        })
        .catch(() => {
          if (active) {
            saveAccessToken("");
            setAuthToken("");
            setAuthReady(true);
          }
        });
    }
    return () => {
      active = false;
      window.removeEventListener("smriti:unauthorized", handleUnauthorized);
    };
  }, []);

  async function submitAuth(event) {
    event.preventDefault();
    setAuthBusy(true);
    setAuthError("");
    try {
      const signingUp = authMode === "signup";
      const acceptingInvite = authMode === "invite";
      const result = await api(
        signingUp
          ? "/api/auth/signup"
          : acceptingInvite
            ? "/api/auth/invitations/accept"
            : "/api/auth/login",
        {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          password: authPassword,
          ...(!acceptingInvite ? { email: authEmail } : { invitation_token: invitationTokenInput }),
          ...(signingUp ? { organization_name: organizationName } : {}),
        }),
        },
      );
      saveAccessToken(result.access_token);
      setAuthToken(result.access_token);
      setCurrentUser(result.user);
      setAuthPassword("");
      setInvitationTokenInput("");
      setPage("Overview");
      setAuthReady(true);
    } catch (exception) {
      setAuthError(exception.message);
    } finally {
      setAuthBusy(false);
    }
  }

  async function signOut() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch (exception) {
      setAuthError(`Signed out locally; server-side revocation could not be confirmed. ${exception.message}`);
    } finally {
      saveAccessToken("");
      setAuthToken("");
      setCurrentUser(null);
      setPage("Landing");
    }
  }

  const load = useCallback(async (query = search, filter = status) => {
    const requestId = ++memoryRequest.current;
    setLoading(true);
    try {
      const data = await api(
        `/api/memories?q=${encodeURIComponent(query)}&status=${encodeURIComponent(filter)}`,
      );
      if (requestId !== memoryRequest.current) return;
      setMemories(data.memories);
      setSelected((previous) =>
        (previous && data.memories.find((memory) => memory.id === previous.id)) ||
        data.memories[0] ||
        null,
      );
      setError("");
    } catch (exception) {
      if (requestId === memoryRequest.current) setError(exception.message);
    } finally {
      if (requestId === memoryRequest.current) setLoading(false);
    }
  }, [search, status]);

  useEffect(() => {
    if (!authToken) return;
    const timer = window.setTimeout(() => load(), search ? 220 : 0);
    return () => window.clearTimeout(timer);
  }, [authToken, load, search, status]);

  useEffect(() => {
    if (!authToken) return;
    api("/api/health").catch((exception) => setError(exception.message));
  }, [authToken]);

  const loadAudit = useCallback(async (query = auditSearch, action = auditAction) => {
    const requestId = ++auditRequest.current;
    setAuditLoading(true);
    try {
      const data = await api(
        `/api/audit?q=${encodeURIComponent(query)}&action=${encodeURIComponent(action)}&limit=500`,
      );
      if (requestId !== auditRequest.current) return;
      setAuditEvents(data.events);
      setAuditActions(data.actions);
      setAuditTotal(data.total);
      if (currentUser?.role === "admin") {
        const [overview, userList] = await Promise.all([
          api("/api/security/overview"),
          api("/api/org/users"),
        ]);
        setSecurityOverview(overview);
        setMembers(userList.members);
      }
      setError("");
    } catch (exception) {
      if (requestId === auditRequest.current) setError(exception.message);
    } finally {
      if (requestId === auditRequest.current) setAuditLoading(false);
    }
  }, [auditAction, auditSearch, currentUser]);

  useEffect(() => {
    if (!authToken) return;
    if (page !== "Security & Audit") return;
    loadAudit(auditSearch, auditAction);
  }, [authToken, page, loadAudit]);

  const loadCorrections = useCallback(async (filter = correctionFilter) => {
    setCorrectionLoading(true);
    try {
      const data = await api(`/api/corrections?status=${encodeURIComponent(filter)}`);
      setCorrections(data.corrections);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setCorrectionLoading(false);
    }
  }, [correctionFilter]);

  useEffect(() => {
    if (!authToken) return;
    if (page === "Correction Review") loadCorrections();
  }, [authToken, page, loadCorrections]);

  useEffect(() => {
    if (!authToken || !selected?.id) {
      setMemoryHistory([]);
      return;
    }
    let current = true;
    api(`/api/memories/${encodeURIComponent(selected.id)}/history`)
      .then((data) => {
        if (current) setMemoryHistory(data.versions);
      })
      .catch((exception) => {
        if (current) setError(exception.message);
      });
    return () => { current = false; };
  }, [authToken, selected?.id]);

  async function openSource(memory) {
    setSourceLoading(true);
    setSourceDenied(false);
    setSourceDocument({ memory_id: memory.id, source: memory.source, title: memory.title });
    try {
      const data = await api(`/api/sources/${encodeURIComponent(memory.id)}`);
      setSourceDocument(data);
    } catch (exception) {
      if (exception.status === 403) {
        setSourceDenied(true);
      } else {
        setError(exception.message);
        setSourceDocument(null);
      }
    } finally {
      setSourceLoading(false);
    }
  }

  async function showDeniedSourceExample() {
    setSourceLoading(true);
    setSourceDenied(false);
    try {
      await api("/api/sources/demo/denied");
      throw new Error("The demo access-denied example unexpectedly returned access.");
    } catch (exception) {
      if (exception.status === 403) {
        setSourceDenied(true);
        setSourceDocument({ title: "Restricted source", source: "restricted-demo.md" });
      } else {
        setError(exception.message);
      }
    } finally {
      setSourceLoading(false);
    }
  }

  async function reviewCorrection(id, decision) {
    setCorrectionBusy(id);
    setError("");
    try {
      const result = await api(`/api/corrections/${encodeURIComponent(id)}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision,
          reviewer: "local-reviewer",
          note: "",
        }),
      });
      if (decision === "approved" && result.memory) setSelected(result.memory);
      await Promise.all([loadCorrections(), load("", "All")]);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setCorrectionBusy("");
    }
  }

  async function loadHandover(project) {
    if (!project) return;
    setHandoverLoading(true);
    setError("");
    try {
      const data = await api(`/api/handover?project=${encodeURIComponent(project)}`);
      setHandover(data);
      setHandoverProject(project);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setHandoverLoading(false);
    }
  }

  async function ask(value = question) {
    const query = value.trim();
    if (!query || busy) return;
    setBusy(true);
    setError("");
    try {
      const preview = await api("/api/privacy/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: query }),
      });
      setPrivacyPreview(preview);
      setPendingQuestion(query);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setBusy(false);
    }
  }

  async function continueWithRetrieval() {
    const query = pendingQuestion;
    setPrivacyPreview(null);
    if (!query) return;
    setBusy(true);
    setPage("Agent Workspace");
    setGraphQuery(query);
    setError("");
    try {
      const data = await api("/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: query }),
      });
      setAnswer(data);
      setQuestion(query);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setBusy(false);
      setPendingQuestion("");
    }
  }

  function startMemoryForm(memory = null) {
    setEditingMemoryId("");
    setDraft(memory
      ? {
          title: `Correction: ${memory.title}`,
          memory_type: memory.memory_type,
          project: memory.project,
          status: memory.status,
          content: "",
          source: memory.source,
          supersedes_id: memory.id,
        }
      : emptyDraft);
    setMemoryFormOpen(true);
  }

  function startEditForm(memory) {
    setEditingMemoryId(memory.id);
    setDraft({
      title: memory.title,
      memory_type: memory.memory_type,
      project: memory.project,
      status: memory.status,
      content: memory.content,
      source: memory.source,
      supersedes_id: "",
      sensitivity: memory.sensitivity || "INTERNAL",
      tags: memory.tags || [],
    });
    setMemoryFormOpen(true);
  }

  async function archiveMemory(memory) {
    try {
      await api(`/api/memories/${encodeURIComponent(memory.id)}/archive`, { method: "POST" });
      await load("", "All");
    } catch (exception) {
      setError(exception.message);
    }
  }

  async function deleteMemory(memory) {
    if (!window.confirm(`Permanently delete “${memory.title}”?`)) return;
    try {
      await api(`/api/memories/${encodeURIComponent(memory.id)}`, { method: "DELETE" });
      setSelected(null);
      await load("", "All");
    } catch (exception) {
      setError(exception.message);
    }
  }

  function openMemory(memory) {
    setSelected(memory);
  }

  async function saveMemory(event) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      let payload = { ...draft };
      if (editingMemoryId) {
        const data = await api(`/api/memories/${encodeURIComponent(editingMemoryId)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        setSelected(data.memory);
        setMemoryFormOpen(false);
        setEditingMemoryId("");
        await load("", "All");
        return;
      }
      const isCorrection = Boolean(payload.supersedes_id);
      if (isCorrection) {
        payload.memory_id = payload.supersedes_id;
        payload.requested_status = payload.status;
        delete payload.supersedes_id;
        delete payload.project;
        delete payload.status;
      }
      const data = await api(isCorrection ? "/api/corrections" : "/api/memories", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (data.memory) setSelected(data.memory);
      setMemoryFormOpen(false);
      setEditingMemoryId("");
      setDraft(emptyDraft);
      setSearch("");
      setStatus("All");
      setPage(isCorrection ? "Correction Review" : "Memory Explorer");
      await load("", "All");
      if (isCorrection) {
        setCorrectionFilter("pending");
        await loadCorrections("pending");
      }
      const audit = await api("/api/audit");
      setAuditEvents(audit.events);
      setAuditActions(audit.actions);
      setAuditTotal(audit.total);
    } catch (exception) {
      setError(exception.message);
    } finally {
      setSaving(false);
    }
  }

  async function refresh() {
    await load();
    if (page === "Security & Audit") {
      await loadAudit();
    }
    if (page === "Correction Review") {
      await loadCorrections();
    }
    if (page === "Knowledge Transfer") {
      await loadHandover(handoverProject || memories[0]?.project || "");
    }
  }

  async function exportAuditCsv() {
    setAuditExporting(true);
    setAuditNotice("");
    setError("");
    try {
      const headers = new Headers();
      if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);
      const response = await fetch(auditExportUrl(auditSearch, auditAction), { headers });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || `CSV export failed (${response.status}).`);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "smriti-nexus-audit.csv";
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setAuditNotice("CSV download started for the matching audit events.");
    } catch (exception) {
      setError(exception.message || "Could not export audit events.");
    } finally {
      setAuditExporting(false);
    }
  }

  function exportHandover() {
    if (!handover?.records?.length) {
      setError("Generate a handover with project records before exporting.");
      return;
    }
    const markdown = [
      `# ${handover.project} handover`,
      "",
      handover.summary,
      "",
      handover.missing_evidence || "",
      "",
      ...handover.records.flatMap((memory) => [
        `## ${memory.title} [${memory.status}]`,
        "",
        memory.content,
        "",
        `Project: ${memory.project}  `,
        `Source: ${memory.source}`,
        "",
      ]),
    ].join("\n");
    const url = URL.createObjectURL(new Blob([markdown], { type: "text/markdown" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${handover.project.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-handover.md`;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const count = (value) => memories.filter((memory) => memory.status === value).length;
  const activeCount = memories.filter(
    (memory) => !["Superseded", "Archived"].includes(memory.status),
  ).length;

  function enterMemorySpace() {
    window.scrollTo({ top: 0, behavior: "instant" });
    setPage("Memory Explorer");
  }

  function enterWorkspace() {
    window.scrollTo({ top: 0, behavior: "instant" });
    setPage("Overview");
  }

  function showLandingPage() {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    window.scrollTo({ top: 0, behavior: "instant" });
    setPage("Landing");
  }

  if (!DEMO_MODE && !authReady) {
    return <main className="auth-screen"><section className="auth-panel"><span className="auth-mark">S✳</span><p>VERIFYING SECURE SESSION</p></section></main>;
  }

  if (!DEMO_MODE && !authToken) {
    return (
      <main className="auth-screen">
        <section className="auth-panel">
          <a className="auth-brand" href="#top"><span className="auth-mark">S✳</span><span>SMRITI <b>NEXUS</b></span></a>
          <small>SECURE ORGANIZATIONAL MEMORY</small>
          <h1>{authMode === "signup" ? "Create a workspace" : authMode === "invite" ? "Accept an invitation" : "Welcome back"}</h1>
          <p>{authMode === "signup" ? "Start an organization workspace. Your account will be its first administrator." : authMode === "invite" ? "Enter the one-time invitation token shared by your organization Admin." : "Sign in to access your organization’s memories."}</p>
          {authError && <div className="auth-error" role="alert">{authError}</div>}
          <form onSubmit={submitAuth}>
            {authMode === "signup" && (
              <label>Organization name
                <input required minLength={2} maxLength={120} autoComplete="organization" value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} />
              </label>
            )}
            {authMode !== "invite" ? (
              <label>Email
                <input required type="email" maxLength={320} autoComplete="email" value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} />
              </label>
            ) : (
              <label>Invitation token
                <input required minLength={32} maxLength={256} autoComplete="off" value={invitationTokenInput} onChange={(event) => setInvitationTokenInput(event.target.value)} />
              </label>
            )}
            <label>Password
              <input required type="password" minLength={authMode === "login" ? 1 : 12} maxLength={128} autoComplete={authMode === "login" ? "current-password" : "new-password"} value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} />
              {authMode !== "login" && <span className="auth-hint">{authMode === "invite" ? "Create a password with at least 12 characters, or enter the existing account password." : "Use at least 12 characters."}</span>}
            </label>
            <button className="primary auth-submit" disabled={authBusy}>{authBusy ? "Please wait…" : authMode === "signup" ? "Create workspace" : authMode === "invite" ? "Accept invitation" : "Sign in"}</button>
          </form>
          <button className="auth-switch" onClick={() => { setAuthMode(authMode === "signup" ? "login" : "signup"); setAuthError(""); }}>
            {authMode === "signup" ? "Already have a workspace? Sign in" : "New to Smriti Nexus? Create a workspace"}
          </button>
          {authMode !== "invite" && <button className="auth-switch" onClick={() => { setAuthMode("invite"); setAuthError(""); }}>Have an organization invitation?</button>}
          {authMode === "invite" && <button className="auth-switch" onClick={() => { setAuthMode("login"); setAuthError(""); }}>Back to sign in</button>}
        </section>
      </main>
    );
  }

  if (page === "Landing") {
    return (
      <Landing
        memories={memories}
        verifiedCount={count("Verified")}
        onEnter={enterWorkspace}
        onWorkspace={enterWorkspace}
      />
    );
  }

  return (
    <div className="app">
      <aside className="rail" aria-label="Main navigation">
        <button
          type="button"
          className="mark"
          aria-label="Back to landing page"
          title="Back to landing page"
          onClick={showLandingPage}
        >
          <span className="rail-mark">S✳</span>
          <span className="rail-brand">Smriti <b>Nexus</b></span>
        </button>
        {nav.filter(([name]) => ["admin", "manager"].includes(currentUser?.role) || !["Correction Review", "Security & Audit"].includes(name)).map(([name, Icon]) => (
          <button
            key={name}
            aria-label={name}
            title={name}
            className={page === name ? "active" : ""}
            onClick={() => setPage(name)}
          >
            <Icon size={18} />
            <span>{name}</span>
          </button>
        ))}
        <div className="railfoot"><span>SN</span><div><b>{currentUser?.email || "Workspace"}</b><small>{currentUser?.role || "member"}</small></div></div>
      </aside>

      <main className="main">
        <header>
          <div className="wordmark">SMRITI <b>NEXUS</b><span>INSTITUTIONAL MEMORY</span></div>
          <div className="header-actions">
            <button className="ghost add-memory" onClick={() => startMemoryForm()}>
              <Plus size={14} /> New memory
            </button>
            {!DEMO_MODE && <button className="ghost" onClick={signOut}>Sign out</button>}
          </div>
          {currentUser?.role === "admin" && (
            <div className="member-management">
              <div><small>ORGANIZATION ACCESS</small><h3>Team members</h3></div>
              <form className="invite-form" onSubmit={createInvitation}>
                <input required type="email" maxLength={320} placeholder="teammate@example.com" aria-label="Invite email" value={inviteEmail} onChange={(event) => setInviteEmail(event.target.value)} />
                <select aria-label="Invite role" value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>
                  <option value="employee">Employee</option>
                  <option value="manager">Manager</option>
                </select>
                <button className="primary">Create invitation</button>
              </form>
              {invitationToken && <p className="invite-token" role="status">One-time invitation token for your secure sharing: <code>{invitationToken}</code></p>}
              <div className="member-list">
                {members.map((member) => (
                  <div key={member.user_id}>
                    <span>{member.email}</span>
                    <select aria-label={`Role for ${member.email}`} value={member.role} disabled={member.role === "admin" && members.filter((item) => item.role === "admin" && item.status === "active").length === 1} onChange={(event) => changeMemberRole(member.user_id, event.target.value)}>
                      <option value="admin">Admin</option>
                      <option value="manager">Manager</option>
                      <option value="employee">Employee</option>
                    </select>
                    <small>{member.status}</small>
                  </div>
                ))}
              </div>
            </div>
          )}
        </header>

        <div className="heading">
          <div>
            <div className="eyebrow">WORKSPACE / MEMORY UNIVERSE / {page.toUpperCase()}</div>
            <h1>{page === "Overview" ? "Institutional memory, connected." : page}</h1>
            <p>A living record of what your organization learned — with evidence attached.</p>
          </div>
          <button className="ghost" onClick={refresh} disabled={loading}>
            {loading ? "Loading…" : "Refresh ↻"}
          </button>
        </div>

        {error && (
          <div className="error" role="alert">
            <span>{error}</span>
            <button aria-label="Dismiss error" onClick={() => setError("")}><X size={15} /></button>
          </div>
        )}

        {page === "Overview" && (
          <>
            <div className="stats">
              <Stat label="ACTIVE MEMORIES" value={activeCount} />
              <Stat label="VERIFIED KNOWLEDGE" value={count("Verified")} />
              <Stat label="UNVERIFIED CLAIMS" value={count("Unverified")} />
              <Stat label="PROJECTS" value={new Set(memories.map((memory) => memory.project)).size} />
            </div>
            <div className="cols">
              <section className="panel">
                <div className="panelhead">
                  <div><small>CONNECTED KNOWLEDGE</small><h2>Memory landscape</h2></div>
                  <button className="link" onClick={() => setPage("Knowledge Graph")}>Explore graph ↗</button>
                </div>
                <Graph memories={memories} onPick={(memory) => {
                  setSelected(memory);
                  setPage("Memory Explorer");
                }} query={graphQuery} />
                <GraphLegend />
              </section>
              <section className="panel">
                <small>AGENT WORKSPACE</small>
                <h2>Ask what the team knows.</h2>
                <p className="muted">Retrieve prior decisions, incidents, and fixes. Responses include source records and confidence limitations.</p>
                {suggestions.map((suggestion) => (
                  <button className="suggest" key={suggestion} onClick={() => ask(suggestion)} disabled={busy}>
                    {suggestion}<ArrowUpRight size={15} />
                  </button>
                ))}
              </section>
            </div>
            <section className="panel recent">
              <div className="panelhead">
                <div><small>RECENT MEMORY</small><h2>Institutional knowledge</h2></div>
                <button className="link" onClick={() => setPage("Memory Explorer")}>View all ↗</button>
              </div>
              {memories.slice(0, 4).map((memory) => (
                <MemoryRow key={memory.id} memory={memory} onClick={() => {
                  setSelected(memory);
                  setPage("Memory Explorer");
                }} />
              ))}
              {!memories.length && <p className="muted">No memories yet. Create one to get started.</p>}
            </section>
          </>
        )}

        {page === "Agent Workspace" && (
          <div className="agent">
            <section className="panel agentmain">
              <div className="agentintro">
                <BrainCircuit size={30} />
                <small>NEXUS AGENT / KEYWORD-DEMO MODE</small>
                <h2>What should we understand?</h2>
                <p>Answers use bounded retrieval over persistent memory records. No external LLM is connected.</p>
              </div>
              <div className="quick">
                {[suggestions[0], "Which fixes are now outdated?", "Prepare a handover for Payment Service."].map((suggestion) => (
                  <button key={suggestion} onClick={() => ask(suggestion)} disabled={busy}>
                    {suggestion}<ChevronRight size={16} />
                  </button>
                ))}
              </div>
              <form onSubmit={(event) => { event.preventDefault(); ask(); }} className="composer">
                <input
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  placeholder="Ask about an incident, decision, or fix…"
                  aria-label="Ask about a memory"
                />
                <button disabled={busy || !question.trim()}>{busy ? "Searching…" : "Retrieve ↗"}</button>
              </form>
              {answer && (
                <div className="answer">
                  <small>✳ EVIDENCE-BACKED RESPONSE</small>
                  <p>{answer.answer}</p>
                  {answer.privacy && (
                    <div className="privacy-decision">
                      <b>Privacy gateway · {answer.privacy.decision}</b>
                      <span>{answer.privacy.reason}</span>
                      <small>Provider: {answer.privacy.provider || "none"} · No external provider is configured</small>
                    </div>
                  )}
                  {answer.sources?.length > 0 ? (
                    <div className="sources" aria-label="Evidence citations">
                      {answer.sources.map((source, index) => (
                        <button key={source.id} onClick={() => {
                          setSelected(source);
                          setSearch("");
                          setStatus("All");
                          openSource(source);
                        }}>
                          <span className="citation-index">[{index + 1}]</span>
                          <span className="citation-source"><b>{source.title}</b><small>{source.source} · {source.status}</small></span>
                          <ExternalLink size={14} aria-hidden="true" />
                        </button>
                      ))}
                    </div>
                  ) : <p className="muted">No matching source records. Try a project, incident, or source-document name.</p>}
                  <small>Trace: {(answer.trace || []).join(" → ")}</small>
                </div>
              )}
            </section>
            <aside className="panel">
              <small>EXECUTION TRACE</small>
              <h2>Observable retrieval</h2>
              {(answer?.trace || ["Run a query to see its execution trace."]).map((step, index) => (
                <div className="trace" key={`${step}-${index}`}>
                  <CheckCircle2 size={15} /><span>{step}</span><b>{String(index + 1).padStart(2, "0")}</b>
                </div>
              ))}
            </aside>
          </div>
        )}

        {page === "Memory Explorer" && (
          <div className="explorer">
            <div className="filters">
              <label>
                <Search size={16} />
                <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search memory, project, or source…" />
                {search && <button className="clear-search" aria-label="Clear search" onClick={() => setSearch("")}><X size={14} /></button>}
              </label>
              <select aria-label="Filter by verification status" value={status} onChange={(event) => setStatus(event.target.value)}>
                {["All", ...statuses].map((value) => <option key={value}>{value}</option>)}
              </select>
            </div>
            <div className="memorygrid">
              <div className="memorylist">
                {memories.map((memory) => (
                  <MemoryRow
                    key={memory.id}
                    memory={memory}
                    selected={selected?.id === memory.id}
                    onClick={() => openMemory(memory)}
                  />
                ))}
                {!memories.length && (
                  <p className="muted empty-state">
                    {loading ? "Searching memories…" : "No memories match these filters."}
                  </p>
                )}
              </div>
              <MemoryDetail
                memory={selected}
                history={memoryHistory}
                canEdit={["admin", "manager"].includes(currentUser?.role)}
                canDelete={currentUser?.role === "admin"}
                onCorrect={() => selected && startMemoryForm(selected)}
                onEdit={() => selected && startEditForm(selected)}
                onArchive={() => selected && archiveMemory(selected)}
                onDelete={() => selected && deleteMemory(selected)}
                onOpenSource={openSource}
              />
            </div>
          </div>
        )}

        {page === "Knowledge Graph" && (
          <section className="panel">
            <small>CONNECTED KNOWLEDGE / INTERACTIVE SELECTOR</small>
            <h2>Explore memory relationships</h2>
            <p className="muted">Search for an incident, issue, or project to focus the graph. Lines group matching records by project only; they do not imply a causal or version relationship.</p>
            <label className="graph-search">
              <Search size={15} />
              <input
                aria-label="Search knowledge graph"
                placeholder="Search a problem, query, project, or source…"
                value={graphQuery}
                onChange={(event) => setGraphQuery(event.target.value)}
              />
              {graphQuery && <button type="button" className="clear-search" aria-label="Clear graph search" onClick={() => setGraphQuery("")}><X size={14} /></button>}
            </label>
            <Graph memories={memories} onPick={(memory) => {
              openMemory(memory);
              setPage("Memory Explorer");
            }} query={graphQuery} />
            <GraphLegend />
          </section>
        )}

        {page === "Incidents & Decisions" && (
          <section className="panel">
            <small>CAUSAL MEMORY</small><h2>Incidents and decisions</h2>
            {memories
              .filter((memory) => ["Incident", "Root cause", "Fix", "Decision", "Constraint"].includes(memory.memory_type))
              .map((memory) => (
                <MemoryRow key={memory.id} memory={memory} onClick={() => {
                  openMemory(memory);
                  setPage("Memory Explorer");
                }} />
              ))}
            {!memories.some((memory) => ["Incident", "Root cause", "Fix", "Decision", "Constraint"].includes(memory.memory_type)) &&
              <p className="muted">No incident or decision memories are available.</p>}
          </section>
        )}

        {page === "Knowledge Transfer" && (
          <section className="panel">
            <div className="panelhead">
              <div><small>KNOWLEDGE TRANSFER CENTER</small><h2>Prepare a project handover</h2></div>
              <button className="primary" onClick={exportHandover} disabled={!handover?.records?.length}>Export Markdown ↓</button>
            </div>
            <p className="muted">Built from current project memories and their evidence. No architecture context is invented.</p>
            <form className="handover-picker" onSubmit={(event) => {
              event.preventDefault();
              loadHandover(handoverProject || memories[0]?.project || "");
            }}>
              <label htmlFor="handover-project">Project</label>
              <select id="handover-project" disabled={handoverLoading} value={handoverProject || memories[0]?.project || ""} onChange={(event) => {
                setHandoverProject(event.target.value);
                setHandover(null);
              }}>
                {[...new Set(memories.map((memory) => memory.project))].map((project) => <option key={project}>{project}</option>)}
              </select>
              <button className="ghost" disabled={handoverLoading || !memories.length}>{handoverLoading ? "Preparing…" : "Generate handover"}</button>
            </form>
            {handover && (
              <div className="handover-content">
                <h3>{handover.project} handover</h3>
                <p className="muted">Generated from {handover.records.length} persisted memory record{handover.records.length === 1 ? "" : "s"}.</p>
                {handover.missing_evidence && <p className="warning">{handover.missing_evidence}</p>}
                <h3>Project memory and evidence</h3>
                {handover.records.map((memory) => (
                  <article className="handover-record" key={memory.id}>
                    <div><b>{memory.title}</b><span>{memory.status} · {memory.memory_type}</span></div>
                    <p>{memory.content}</p>
                    <button className="link" onClick={() => openSource(memory)}><FileText size={13} /> {memory.source}</button>
                  </article>
                ))}
                {!handover.records.length && <p className="muted">No records are available for this project.</p>}
              </div>
            )}
          </section>
        )}

        {page === "Correction Review" && (
          <section className="panel">
            <div className="panelhead">
              <div><small>MEMORY GOVERNANCE</small><h2>Correction approval queue</h2></div>
              <div className="review-toolbar flex items-center gap-2">
              <button className="primary" onClick={() => {
                setSearch("");
                setStatus("All");
                setPage("Memory Explorer");
              }}>
                Create correction
              </button>
              <select aria-label="Filter correction requests" value={correctionFilter} onChange={(event) => {
                setCorrectionFilter(event.target.value);
              }}>
                  <option value="pending">Pending review</option>
                  <option value="approved">Approved</option>
                  <option value="rejected">Rejected</option>
                  <option value="All">All requests</option>
                </select>
                <button className="ghost" onClick={() => loadCorrections()} disabled={correctionLoading}>{correctionLoading ? "Loading…" : "Refresh"}</button>
              </div>
            </div>
            <p className="muted">Proposed corrections remain pending until reviewed. Approval creates a new version and supersedes the prior record; rejection leaves it unchanged. To propose one, choose a current memory in Memory Explorer and select Create correction.</p>
            {correctionLoading && !corrections.length && <p className="muted">Loading review requests…</p>}
            {!correctionLoading && !corrections.length && (
              <div className="empty-state muted">
                <p>
                  {correctionFilter === "pending"
                    ? "No corrections are waiting for review."
                    : "No corrections match this filter."}
                </p>
                {correctionFilter === "pending" && (
                  <p>
                    To request a correction, select a current memory in Memory Explorer.
                    <button className="link" onClick={() => setPage("Memory Explorer")}>
                      Open Memory Explorer ↗
                    </button>
                  </p>
                )}
              </div>
            )}
            <div className="correction-queue">
              {corrections.map((correction) => (
                <article className="correction-card" key={correction.id}>
                  <div className="correction-card-heading">
                    <div><small>PROPOSED CORRECTION · {correction.project} · {correction.proposed_status || "status unchanged"}</small><h3>{correction.title}</h3></div>
                    <span className={`pending-badge ${correction.status}`}>{correction.status}</span>
                  </div>
                  <p>{correction.content}</p>
                  <div className="correction-meta">Replaces: {correction.supersedes_title || correction.supersedes_id} · Requested {new Date(correction.created_at).toLocaleString()}</div>
                  {correction.status === "pending" ? (
                    <div className="correction-actions">
                      <button className="ghost" disabled={Boolean(correctionBusy)} onClick={() => reviewCorrection(correction.id, "rejected")}>{correctionBusy === correction.id ? "Saving…" : "Reject"}</button>
                      <button className="primary" disabled={Boolean(correctionBusy)} onClick={() => reviewCorrection(correction.id, "approved")}>{correctionBusy === correction.id ? "Saving…" : "Approve correction"}</button>
                    </div>
                  ) : (
                    <div className="correction-meta">Reviewed {correction.reviewer ? `by ${correction.reviewer}` : ""}{correction.reviewed_at ? ` · ${new Date(correction.reviewed_at).toLocaleString()}` : ""}{correction.review_note ? ` · ${correction.review_note}` : ""}</div>
                  )}
                </article>
              ))}
            </div>
          </section>
        )}

        {page === "Security & Audit" && (
          <section className="panel">
            <div className="panelhead audit-heading">
              <div><small>TRUST LAYER</small><h2>Security & audit</h2></div>
              <div className="audit-actions">
                <button className="ghost" onClick={() => loadAudit()} disabled={auditLoading}>
                  <RefreshCw size={13} /> {auditLoading ? "Refreshing…" : "Refresh"}
                </button>
                <button className="ghost audit-export" onClick={exportAuditCsv} disabled={auditExporting}>
                  <Download size={14} /> Export CSV
                </button>
              </div>
            </div>
            {currentUser?.role === "admin" && securityOverview && (
              <div className="security-summary" aria-label="Security status">
                <div><small>FAILED SIGN-INS / 24H</small><b>{securityOverview.alerts.failed_logins_last_24h}</b></div>
                <div><small>RATE LIMITS / 24H</small><b>{securityOverview.alerts.rate_limits_last_24h}</b></div>
                <div><small>DATABASE</small><b>{securityOverview.configuration.database}</b></div>
                <div><small>EXTERNAL AI</small><b>{securityOverview.configuration.external_ai_provider}</b></div>
                <div><small>MANAGED KMS</small><b>{securityOverview.configuration.managed_kms}</b></div>
              </div>
            )}
            {currentUser?.role === "admin" && securityOverview?.events?.length > 0 && (
              <div className="security-events">
                <small>RECENT AUTHENTICATION, PRIVACY, AND MEMORY EVENTS</small>
                {securityOverview.events.slice(0, 8).map((event) => (
                  <div key={`${event.seq}-${event.action}`}>
                    <b>{event.action}</b><span>{event.severity}</span><time>{new Date(event.created_at).toLocaleString()}</time>
                  </div>
                ))}
              </div>
            )}
            <p className="muted">Security events and privacy decisions are scoped to your organization. Sensitive event details are restricted to administrators.</p>
            <p>Memory creation, correction requests, and review decisions are shown here. Other audit history remains stored.</p>
            <form className="audit-toolbar" onSubmit={(event) => {
              event.preventDefault();
              setAuditNotice("");
              loadAudit(auditSearch, auditAction);
            }}>
              <label className="audit-search">
                <Search size={15} />
                <input
                  aria-label="Search audit events"
                  placeholder="Search actor, action, resource, or outcome…"
                  value={auditSearch}
                  onChange={(event) => setAuditSearch(event.target.value)}
                />
                {auditSearch && <button type="button" className="clear-search" aria-label="Clear audit search" onClick={() => setAuditSearch("")}><X size={14} /></button>}
              </label>
              <select aria-label="Filter audit action" value={auditAction} onChange={(event) => {
                const action = event.target.value;
                setAuditAction(action);
                setAuditNotice("");
                loadAudit(auditSearch, action);
              }}>
                <option value="memory">Created and corrected memories</option>
                {auditActions.map((action) => <option key={action} value={action}>{action}</option>)}
              </select>
              <button className="ghost audit-search-submit" type="submit" disabled={auditLoading}>
                <Search size={13} /> Search
              </button>
              <span className="audit-count">{auditLoading ? "Updating…" : `${auditEvents.length} of ${auditTotal} events`}</span>
            </form>
            {auditNotice && <p className="audit-notice" role="status">{auditNotice}</p>}
            <div className="audit-list" role="table" aria-label="Audit events">
              <div className="audit-event audit-event-head" role="row">
                <span role="columnheader">Time</span>
                <span role="columnheader">Action / Resource</span>
                <span role="columnheader">Actor / Outcome</span>
              </div>
              {auditEvents.map((event) => (
                <div className="audit-event" key={event.id} role="row">
                  <span role="cell">{new Date(event.created_at).toLocaleString()}</span>
                  <span role="cell"><b className="audit-action">{event.action}</b><small>{event.resource_type}{event.resource_id ? ` · ${event.resource_id}` : ""}</small></span>
                  <span role="cell">{event.actor}<small>{event.outcome}</small></span>
                </div>
              ))}
              {!auditEvents.length && <p className="muted audit-empty">{auditLoading ? "Loading audit events…" : auditTotal ? "No events match those filters." : "No audit events have been recorded yet."}</p>}
            </div>
          </section>
        )}

        <footer>SMRITI NEXUS <span>REMEMBER THE WHY. PRESERVE THE HOW. EMPOWER THE NEXT.</span><span>PORTABLE MVP / 0.1</span></footer>
      </main>

      {memoryFormOpen && (
        <div className="modal-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget && !saving) setMemoryFormOpen(false);
        }}>
          <form className="memory-form panel" onSubmit={saveMemory}>
            <div className="panelhead">
              <div><small>{editingMemoryId ? "UPDATE RECORD" : draft.supersedes_id ? "REVIEW REQUIRED" : "NEW RECORD"}</small><h2>{editingMemoryId ? "Edit memory" : draft.supersedes_id ? "Propose a correction" : "Add a memory"}</h2></div>
              <button type="button" className="icon-button" aria-label="Close form" onClick={() => setMemoryFormOpen(false)} disabled={saving}><X size={18} /></button>
            </div>
            <label>Title<input required maxLength={180} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></label>
            <div className="form-row">
              <label>Type<input maxLength={60} value={draft.memory_type} onChange={(event) => setDraft({ ...draft, memory_type: event.target.value })} /></label>
              <label>Project<input required maxLength={120} value={draft.project} onChange={(event) => setDraft({ ...draft, project: event.target.value })} /></label>
            </div>
            <label>Verification status
              <select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
                {statuses.map((value) => <option key={value}>{value}</option>)}
              </select>
            </label>
            <label>Evidence / details<textarea required maxLength={12000} rows={5} value={draft.content} onChange={(event) => setDraft({ ...draft, content: event.target.value })} /></label>
            <label>Source<input maxLength={240} value={draft.source} onChange={(event) => setDraft({ ...draft, source: event.target.value })} /></label>
            {!draft.supersedes_id && (
              <>
                <label>Sensitivity classification
                  <select value={draft.sensitivity || "INTERNAL"} onChange={(event) => setDraft({ ...draft, sensitivity: event.target.value })}>
                    {["PUBLIC", "INTERNAL", "CONFIDENTIAL", "TOP_SECRET"].map((value) => <option key={value}>{value}</option>)}
                  </select>
                </label>
                <label>Tags<input maxLength={1200} value={(draft.tags || []).join(", ")} onChange={(event) => setDraft({ ...draft, tags: event.target.value.split(",").map((tag) => tag.trim()).filter(Boolean).slice(0, 30) })} placeholder="incident, payments" /></label>
              </>
            )}
            <div className="form-actions">
              <button type="button" className="ghost" onClick={() => setMemoryFormOpen(false)} disabled={saving}>Cancel</button>
              <button className="primary" disabled={saving}>{saving ? "Submitting…" : editingMemoryId ? "Save changes" : draft.supersedes_id ? "Submit for approval" : "Save memory"}</button>
            </div>
          </form>
        </div>
      )}
      {privacyPreview && (
        <div className="modal-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget) {
            setPrivacyPreview(null);
            setPendingQuestion("");
          }
        }}>
          <section className="privacy-dialog panel" role="dialog" aria-modal="true" aria-labelledby="privacy-dialog-title">
            <div className="panelhead">
              <div><small>AI PRIVACY GATEWAY / PREVIEW</small><h2 id="privacy-dialog-title">Review before retrieval</h2></div>
              <button className="icon-button" aria-label="Close privacy preview" onClick={() => { setPrivacyPreview(null); setPendingQuestion(""); }}><X size={18} /></button>
            </div>
            <p className="privacy-reason"><b>{privacyPreview.decision.toUpperCase()}</b> · {privacyPreview.reason}</p>
            <div className="privacy-preview">
              <small>REDACTED QUESTION</small>
              <p>{privacyPreview.safe_question}</p>
              <small>DATA CATEGORIES · {privacyPreview.categories.join(", ")}</small>
              {privacyPreview.redacted_categories.length > 0 && <small>REDACTED · {privacyPreview.redacted_categories.join(", ")}</small>}
              {privacyPreview.preview.map((item) => (
                <article key={item.memory_id}>
                  <b>{item.title}</b><small>{item.sensitivity}</small><p>{item.excerpt}</p>
                </article>
              ))}
            </div>
            <p className="muted">No external AI provider is configured. Continuing runs the existing local retrieval only; nothing is sent to an external model.</p>
            <div className="form-actions">
              <button className="ghost" onClick={() => { setPrivacyPreview(null); setPendingQuestion(""); }}>Cancel</button>
              {privacyPreview.decision !== "blocked" && <button className="primary" onClick={continueWithRetrieval}>Continue to local retrieval</button>}
            </div>
          </section>
        </div>
      )}
      {sourceDocument && (
        <div className="modal-backdrop" onMouseDown={(event) => {
          if (event.target === event.currentTarget && !sourceLoading) setSourceDocument(null);
        }}>
          <section className="source-dialog panel" role="dialog" aria-modal="true" aria-labelledby="source-dialog-title">
            <div className="panelhead">
              <div><small>SOURCE DOCUMENT / LOCAL DEMO ACCESS</small><h2 id="source-dialog-title">{sourceDocument.title || sourceDocument.source}</h2></div>
              <button className="icon-button" aria-label="Close source preview" onClick={() => setSourceDocument(null)}><X size={18} /></button>
            </div>
            {sourceLoading ? <p className="muted">Loading source document…</p> : sourceDenied ? (
              <div className="access-denied flex gap-3 p-4" role="status">
                <LockKeyhole size={22} />
                <div><b>Access denied</b><p>This demo request is forbidden by the source-access API. No document content was returned. This demonstrates the denied-access UI; it is not production authentication.</p></div>
              </div>
            ) : (
              <>
                <div className="source-provenance">{sourceDocument.source} · {sourceDocument.memory_id}</div>
                <p className="source-demo-note">Evidence excerpt from this saved memory. The original source file is not stored in this local MVP.</p>
                <pre className="source-document-content">{sourceDocument.content}</pre>
              </>
            )}
            {!sourceDenied && <button className="link demo-denied-link" onClick={showDeniedSourceExample}><LockKeyhole size={14} /> Show access-denied example (demo)</button>}
          </section>
        </div>
      )}
    </div>
  );
}

function Landing({ memories, verifiedCount, onEnter, onWorkspace }) {
  const projectCounts = new Map();
  memories.forEach((memory) => {
    projectCounts.set(memory.project, (projectCounts.get(memory.project) || 0) + 1);
  });
  const featuredProject = [...projectCounts.entries()].sort((a, b) => b[1] - a[1])[0];
  const featuredMemory = memories.find((memory) => memory.status === "Verified") || memories[0];

  return (
    <main className="landing">
      <header className="landing-header">
        <a className="landing-brand" href="#top" aria-label="Smriti Nexus home">
          <span className="landing-mark">S✳</span>
          <span>SMRITI <b>NEXUS</b></span>
        </a>
        <div className="landing-status"><i /> INSTITUTIONAL INTELLIGENCE <span>/</span> 01.0</div>
        <button className="landing-enter-top" onClick={onWorkspace}>Enter workspace <ArrowUpRight size={14} /></button>
      </header>

      <section className="landing-hero" id="top">
        <div className="landing-copy">
          <div className="landing-kicker"><i /> THE LIVING MEMORY UNIVERSE</div>
          <h1>Your organization’s <em>memory, alive.</em></h1>
          <p className="landing-description">
            An intelligent institutional memory that connects knowledge,
            preserves the why behind decisions, and helps every teammate
            move forward with confidence.
          </p>
          <div className="landing-ctas">
            <button className="landing-primary" onClick={onEnter}>Enter Memory Space <ArrowUpRight size={16} /></button>
            <a
              className="landing-secondary"
              href="#how-it-works"
              onClick={(event) => {
                event.preventDefault();
                document.getElementById("how-it-works").scrollIntoView({ behavior: "smooth", block: "start" });
              }}
            >
              Explore how it works <span>↓</span>
            </a>
          </div>

          <div className="landing-pillars">
            <div><span className="pillar-icon"><Layers size={15} /></span><b>Persistent memory</b><small>Knowledge that survives handover</small></div>
            <div><span className="pillar-icon"><GitBranch size={15} /></span><b>Connected knowledge</b><small>Context beyond keyword search</small></div>
            <div><span className="pillar-icon"><CheckCircle2 size={15} /></span><b>Verified intelligence</b><small>Evidence over guesswork</small></div>
          </div>
        </div>

        <div className="landing-visual" aria-label="Illustration of connected organizational memories">
          <div className="visual-coordinate">LIVE KNOWLEDGE NETWORK<br />NODE FIELD / 07.42.19</div>
          <div className="visual-orbits orbit-one" />
          <div className="visual-orbits orbit-two" />
          <div className="visual-orbits orbit-three" />
          <svg className="landing-network-lines" viewBox="0 0 800 540" preserveAspectRatio="none" aria-hidden="true">
            <defs>
              <linearGradient id="networkStroke" x1="0" x2="1" y1="0" y2="1">
                <stop offset="0" stopColor="#133b29" stopOpacity=".05" />
                <stop offset=".48" stopColor="#38e990" stopOpacity=".95" />
                <stop offset="1" stopColor="#31d985" stopOpacity=".28" />
              </linearGradient>
              <radialGradient id="nodeGlow">
                <stop offset="0" stopColor="#64ffac" stopOpacity=".9" />
                <stop offset="1" stopColor="#37f191" stopOpacity="0" />
              </radialGradient>
            </defs>
            <path className="network-wave" d="M0 418 C145 372 168 452 300 366 S412 220 510 259 S625 326 800 129" />
            <path className="network-strand" d="M0 454 C170 398 246 426 366 347 S499 288 800 289" />
            <path className="network-strand" d="M0 485 C159 437 271 447 384 391 S561 335 800 343" />
            <path className="network-strand" d="M0 508 C186 469 272 493 426 420 S597 383 800 389" />
            <path className="network-strand" d="M154 540 C269 431 307 311 437 255 S665 281 800 225" />
            <circle cx="510" cy="259" r="43" fill="url(#nodeGlow)" />
            <circle className="network-core" cx="510" cy="259" r="9" />
          </svg>
          <span className="network-node-label">MEMORY / 001</span>
          <div className="visual-card connected-card">
            <i />
            <div><small>CONNECTED ENTITY</small><b>{featuredProject?.[0] || "Your workspace"}</b><span>{featuredProject ? `${featuredProject[1]} memories linked` : "Your saved memories appear here"}</span></div>
          </div>
          <div className="visual-card insight-card">
            <i />
            <div><small>{featuredMemory?.status === "Verified" ? "VERIFIED INSIGHT" : "MEMORY INSIGHT"}</small><b>{featuredMemory?.title || "Evidence-backed knowledge"}</b><span>{featuredMemory ? `Evidence · ${featuredMemory.source}` : "Sources attached"}</span></div>
            <CheckCircle2 size={14} />
          </div>
        </div>
      </section>

      <section className="landing-process" id="how-it-works" tabIndex={-1}>
        <div className="process-heading">
          <div>
            <small>HOW MEMORY BECOMES MOMENTUM</small>
            <h2>From what happened to what happens next.</h2>
          </div>
          <p>Turn team experience into useful context that people can find, verify, and carry forward.</p>
        </div>
        <div className="process-cards">
          {[
            [FileText, "Capture", "Save decisions, incidents, fixes, and the evidence behind them."],
            [GitBranch, "Connect", "Find related knowledge by project, query, or source."],
            [CheckCircle2, "Verify", "See a record’s status and source before relying on it."],
            [ArrowUpRight, "Transfer", "Bring the context forward for the next person or team."],
          ].map(([Icon, step, description], index) => (
            <article className="process-card" key={step}>
              <div className="process-card-top"><span>0{index + 1}</span><Icon size={18} /></div>
              <h3>{step}</h3>
              <p>{description}</p>
            </article>
          ))}
        </div>
        <div className="landing-metrics">
          <span>{memories.length} <small>MEMORIES</small></span>
          <span>{verifiedCount} <small>VERIFIED</small></span>
          <span>{projectCounts.size} <small>PROJECTS</small></span>
        </div>
      </section>
      <footer className="landing-footer"><span>SMRITI NEXUS</span><span>REMEMBER THE WHY. PRESERVE THE HOW. EMPOWER THE NEXT.</span><span>SECURE WORKSPACE / 0.2</span></footer>
    </main>
  );
}

function Stat({ label, value }) {
  return <div className="stat"><small>{label}</small><strong>{String(value).padStart(2, "0")}</strong><span>Persistent workspace records</span></div>;
}

function MemoryRow({ memory, onClick, selected }) {
  return (
    <button className={`memoryrow ${selected ? "selected" : ""}`} onClick={onClick}>
      <div><small>{memory.memory_type} / {memory.status}</small><span>{memory.project}</span></div>
      <h3>{memory.title}</h3>
      <p>{memory.content}</p>
      <small className="sourcehint">SOURCE · {memory.source} · V{memory.version}</small>
    </button>
  );
}

function MemoryDetail({ memory, history, canEdit, canDelete, onCorrect, onEdit, onArchive, onDelete, onOpenSource }) {
  return (
    <section className="panel detail">
      {memory ? (
        <>
          <small>MEMORY RECORD / VERSION {memory.version}</small>
          <h2>{memory.title}</h2>
          <div className="metadata">{memory.memory_type} · {memory.project} · {memory.status}</div>
          <div className="metadata">Sensitivity · {memory.sensitivity || "INTERNAL"}{memory.tags?.length ? ` · Tags: ${memory.tags.join(", ")}` : ""}</div>
          <p>{memory.content}</p>
          <button className="source source-open" onClick={() => onOpenSource(memory)}>
            <small>SOURCE PROVENANCE · OPEN PREVIEW</small>
            <b><FileText size={15} />{memory.source}<ExternalLink size={13} /></b>
            <span>Updated {memory.updated_at}</span>
          </button>
          <div className="version-history">
            <div className="timeline"><History size={17} /><div><b>Version history</b><p>{history.length} linked version{history.length === 1 ? "" : "s"}</p></div></div>
            {history.map((version) => (
              <article className={`version-entry ${version.id === memory.id ? "current" : ""}`} key={version.id}>
                <div><b>Version {version.version}</b><span>{version.status}</span></div>
                <p>{version.title}</p>
                <small>{new Date(version.created_at).toLocaleString()} · {version.source}</small>
              </article>
            ))}
          </div>
          <button
            className="ghost correction"
            onClick={onCorrect}
            disabled={["Superseded", "Archived"].includes(memory.status)}
            title={["Superseded", "Archived"].includes(memory.status) ? "Only current memories can be corrected." : undefined}
          >
            Create correction ↗
          </button>
          {canEdit && (
            <div className="memory-actions">
              <button className="ghost" onClick={() => onEdit(memory)}>Edit</button>
              {memory.status !== "Archived" && <button className="ghost" onClick={() => onArchive(memory)}>Archive</button>}
              {canDelete && <button className="ghost" onClick={() => onDelete(memory)}>Delete</button>}
            </div>
          )}
        </>
      ) : <p>Select a memory to inspect it.</p>}
    </section>
  );
}

function Graph({ memories, onPick, query = "" }) {
  const maxNodes = 24;
  const stopWords = new Set(["the", "and", "for", "with", "what", "how", "why", "from", "this", "that", "does", "did", "into", "about"]);
  const queryWords = [...new Set(query.toLowerCase().match(/[a-z0-9]+/g) || [])]
    .filter((word) => word.length > 2 && !stopWords.has(word));
  const rankedMemories = queryWords.length
    ? memories
      .map((memory, index) => {
        const haystack = `${memory.title} ${memory.content} ${memory.project} ${memory.source} ${memory.memory_type}`.toLowerCase();
        const score = queryWords.reduce((total, word) => total + (haystack.includes(word) ? 1 : 0), 0);
        return { memory, index, score };
      })
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score || a.index - b.index)
      .map((item) => item.memory)
    : memories;
  const visibleMemories = rankedMemories.slice(0, maxNodes);
  const projects = [...new Set(visibleMemories.map((memory) => memory.project || "Unassigned project"))];
  const groups = new Map(projects.map((project) => [project, visibleMemories.filter((memory) => (memory.project || "Unassigned project") === project)]));
  const nodes = [];
  const edges = [];
  projects.forEach((project, projectIndex) => {
    const projectNodes = groups.get(project);
    projectNodes.forEach((memory, index) => {
      const hasMultipleColumns = projectNodes.length > 3;
      const projectColumn = hasMultipleColumns ? index % 2 : 0;
      const projectRow = hasMultipleColumns ? Math.floor(index / 2) : index;
      const x = projectIndex * 470 + projectColumn * 235 + 24;
      const y = projectRow * 135 + 60;
      nodes.push({
        id: memory.id,
        position: { x, y },
        data: { label: `${memory.title}\n${project} · ${memory.status}` },
        className: `memory-node status-${memory.status.toLowerCase()}`,
        style: { width: 220 },
      });
      if (index > 0) {
        edges.push({
          id: `${projectNodes[index - 1].id}-${memory.id}`,
          source: projectNodes[index - 1].id,
          target: memory.id,
          label: `same project · ${project}`,
          type: "smoothstep",
          style: { stroke: "#5b9f70", strokeDasharray: "5 4" },
          labelStyle: { fill: "#b7c8bb", fontSize: 10 },
          labelBgStyle: { fill: "#0d1710" },
        });
      }
    });
  });
  const memoriesById = new Map(visibleMemories.map((memory) => [memory.id, memory]));
  function handleNodeClick(_event, node) {
    const memory = memoriesById.get(node.id);
    if (memory) onPick(memory);
  }

  return (
    <div className="graph react-memory-graph">
      {visibleMemories.length > 0 ? (
        <>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodeClick={handleNodeClick}
            fitView
            fitViewOptions={{ padding: 0.25 }}
            minZoom={0.2}
            maxZoom={1.5}
            attributionPosition="bottom-left"
            proOptions={{ hideAttribution: false }}
          >
            <Background color="#294233" gap={28} size={1} />
            <MiniMap pannable zoomable nodeColor={(node) => node.className?.includes("verified") ? "#66e6a0" : "#c9af65"} />
            <Controls />
          </ReactFlow>
          {rankedMemories.length > maxNodes && (
            <span className="graph-truncated">Showing {maxNodes} of {rankedMemories.length} matches · open Memory Explorer for all</span>
          )}
        </>
      ) : <p className="graph-empty">{query.trim() ? "No saved memories match this search. Try another keyword or clear the search." : "No memories to display."}</p>}
    </div>
  );
}

function GraphLegend() {
  return (
    <div className="graph-legend" aria-label="Knowledge graph legend">
      <span><i className="status-dot verified" />Verified</span>
      <span><i className="status-dot unverified" />Unverified</span>
      <span><i className="status-dot superseded" />Superseded</span>
      <span><i className="status-dot disputed" />Disputed</span>
      <span><i className="status-dot archived" />Archived</span>
      <span><i className="project-link" />Same project</span>
    </div>
  );
}
