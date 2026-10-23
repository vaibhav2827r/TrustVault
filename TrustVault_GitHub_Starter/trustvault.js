/**
 * TrustVault — secure document-sharing MVP (JavaScript version)
 *
 * Run:
 *   node trustvault.js
 *
 * Then open http://127.0.0.1:3000
 *
 * This is a demo scaffold for the Snovasys hiring assignment.
 * It uses in-memory demo data and MUST NOT be used for real confidential
 * documents. Restarting the server resets data. It stores document metadata
 * only, not file bytes. Production needs real authentication, persistent
 * database storage, private object storage, server-side authorization, and
 * tamper-resistant audit logging.
 */

"use strict";

const http = require("node:http");
const { randomUUID } = require("node:crypto");
const { URL } = require("node:url");

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);

const organizations = [
  { id: "org-acme", name: "Acme Finance" },
  { id: "org-northstar", name: "Northstar Health" },
];

const users = [
  { id: "user-admin", name: "Asha Admin", organizationId: "org-acme", role: "Admin" },
  { id: "user-manager", name: "Ravi Manager", organizationId: "org-acme", role: "Manager" },
  { id: "user-viewer", name: "Maya Viewer", organizationId: "org-acme", role: "Viewer" },
  { id: "user-other-company", name: "Noah OtherCo", organizationId: "org-northstar", role: "Admin" },
];

const documents = [
  {
    id: "doc-welcome",
    organizationId: "org-acme",
    ownerId: "user-admin",
    name: "Welcome.pdf",
    contentType: "application/pdf",
    createdAt: new Date().toISOString(),
    shares: [{ userId: "user-viewer", permission: "view" }],
  },
];

const auditLogs = [];

function nowIso() {
  return new Date().toISOString();
}

function findUser(userId) {
  return users.find((user) => user.id === userId) || null;
}

function findDocument(documentId) {
  return documents.find((document) => document.id === documentId) || null;
}

function addAuditLog({
  actorId,
  organizationId,
  action,
  documentId = null,
  outcome = "success",
  details = "",
}) {
  // Demo only: this in-memory log is not tamper-proof.
  auditLogs.unshift({
    id: randomUUID(),
    actorId,
    organizationId,
    action,
    documentId,
    outcome,
    details,
    timestamp: nowIso(),
  });
}

function canReadDocument(user, document) {
  if (!user || !document) return false;

  const sameOrganization = user.organizationId === document.organizationId;
  if (
    sameOrganization &&
    (document.ownerId === user.id || user.role === "Admin" || user.role === "Manager")
  ) {
    return true;
  }

  return document.shares.some(
    (share) =>
      share.userId === user.id &&
      (share.permission === "view" || share.permission === "edit")
  );
}

function canManageDocument(user, document) {
  return Boolean(
    user &&
      document &&
      user.organizationId === document.organizationId &&
      (user.role === "Admin" ||
        document.ownerId === user.id ||
        user.role === "Manager")
  );
}

function safeDocument(document) {
  return {
    id: document.id,
    organizationId: document.organizationId,
    ownerId: document.ownerId,
    name: document.name,
    contentType: document.contentType,
    createdAt: document.createdAt,
    shares: document.shares,
  };
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

function sendHtml(res, html) {
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
  });
  res.end(html);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > 1_000_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        const parsed = JSON.parse(body);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          return reject(new Error("JSON body must be an object"));
        }
        resolve(parsed);
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function getRequestUser(url) {
  // Demo identity only; this is NOT authentication.
  const userId = url.searchParams.get("userId") || "user-admin";
  return findUser(userId);
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustVault — Secure Document Sharing</title>
<style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#172033;background:#f4f7fb}
*{box-sizing:border-box}body{margin:0}header{background:#111d35;color:white;padding:22px max(20px,calc((100% - 1080px)/2))}
header h1{margin:0;font-size:25px}header p{margin:7px 0 0;color:#c4cee0}
main{max-width:1080px;margin:26px auto;padding:0 18px 40px}
.toolbar,.panel,.stat{background:white;border:1px solid #e1e7f0;border-radius:14px;padding:18px}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:12px;justify-content:space-between;margin-bottom:18px}
select,input,button{font:inherit;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px}
button{cursor:pointer;background:#2457d6;color:white;border-color:#2457d6;font-weight:600}
button.secondary{background:white;color:#23314d;border-color:#cbd5e1}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:18px}
.stat span{display:block;color:#64748b;font-size:13px}.stat strong{display:block;font-size:26px;margin-top:8px}
.grid{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(280px,.9fr);gap:18px}
h2{font-size:17px;margin:0 0 15px}.muted{color:#64748b;font-size:13px}
.doc{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:13px 0;border-top:1px solid #edf1f6}
.doc strong{display:block;overflow-wrap:anywhere}.doc small{display:block;margin-top:5px;color:#64748b}
.actions{display:flex;flex-wrap:wrap;gap:7px}.actions button{padding:7px 9px;font-size:12px}
form{display:grid;gap:10px}label{display:grid;gap:5px;font-size:13px;color:#475569}
.notice{margin-top:16px;background:#fff8e6;border:1px solid #f0d99c;padding:12px;border-radius:10px;color:#704d00;font-size:13px}
#message{margin:12px 0;min-height:20px;font-size:14px}.audit-row{padding:10px 0;border-top:1px solid #edf1f6;font-size:13px;overflow-wrap:anywhere}
.audit-row strong{display:block}@media(max-width:760px){.grid,.stats{grid-template-columns:1fr}.toolbar{align-items:stretch}}
</style></head>
<body><header><h1>🔐 TrustVault</h1><p>Secure document sharing with an audit trail</p></header>
<main>
<section class="toolbar"><div><label for="userSelect">Demo identity</label>
<select id="userSelect">
<option value="user-admin">Asha Admin — Acme Finance</option>
<option value="user-manager">Ravi Manager — Acme Finance</option>
<option value="user-viewer">Maya Viewer — Acme Finance</option>
<option value="user-other-company">Noah Admin — Northstar Health</option>
</select></div><button class="secondary" id="refreshBtn">Refresh dashboard</button></section>
<div id="message" role="status"></div>
<section class="stats">
<div class="stat"><span>Visible documents</span><strong id="docCount">—</strong></div>
<div class="stat"><span>Organization</span><strong id="orgName" style="font-size:18px">—</strong></div>
<div class="stat"><span>Recent audit events</span><strong id="auditCount">—</strong></div></section>
<section class="grid"><div class="panel"><h2>Documents</h2><div id="documents"><p class="muted">Loading…</p></div>
<div class="notice">Demo only: uploads create document metadata. No file bytes are stored.</div></div>
<div><section class="panel"><h2>Add a demo document</h2><form id="uploadForm">
<label>Document name<input id="docName" required maxlength="120" placeholder="Quarterly-report.pdf"></label>
<label>Content type<select id="contentType"><option value="application/pdf">PDF</option><option value="text/plain">Text</option><option value="application/vnd.openxmlformats-officedocument.wordprocessingml.document">Word document</option></select></label>
<button type="submit">Add document metadata</button></form></section>
<section class="panel" style="margin-top:18px"><h2>Audit trail</h2><div id="auditLogs"><p class="muted">Loading…</p></div></section></div></section>
<p class="muted" style="margin-top:20px">Hiring-project prototype · Node.js standard library · No third-party packages</p>
</main>
<script>
const $=id=>document.getElementById(id), userId=()=>$('userSelect').value;
const esc=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,options={}){const sep=path.includes('?')?'&':'?';const r=await fetch(path+sep+'userId='+encodeURIComponent(userId()),{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function message(t,bad=false){$('message').textContent=t;$('message').style.color=bad?'#b42318':'#187443'}
async function load(){try{const d=await api('/api/dashboard');$('docCount').textContent=d.documents.length;$('orgName').textContent=d.organization.name;$('auditCount').textContent=d.auditLogs.length;
$('documents').innerHTML=d.documents.length?d.documents.map(x=>\`<div class="doc"><div><strong>📄 \${esc(x.name)}</strong><small>Owner: \${esc(x.ownerId)} · \${esc(new Date(x.createdAt).toLocaleString())}</small></div><div class="actions"><button class="secondary" onclick="viewDoc('\${encodeURIComponent(x.id)}')">View</button><button class="secondary" onclick="shareDoc('\${encodeURIComponent(x.id)}')">Share</button></div></div>\`).join(''):'<p class="muted">No documents visible to this user.</p>';
$('auditLogs').innerHTML=d.auditLogs.length?d.auditLogs.slice(0,12).map(x=>\`<div class="audit-row"><strong>\${esc(x.action)} · \${esc(x.outcome)}</strong><span>\${esc(x.actorId)} · \${esc(new Date(x.timestamp).toLocaleString())}</span><div class="muted">\${esc(x.details||x.documentId||'')}</div></div>\`).join(''):'<p class="muted">No audit events yet.</p>';
}catch(e){message(e.message,true)}}
async function viewDoc(id){try{const d=await api('/api/documents/'+id);message('Access granted to metadata for "'+d.document.name+'". No file content is stored in this demo.')}catch(e){message(e.message,true)}}
async function shareDoc(id){const recipientId=prompt('Share with user ID: user-admin, user-manager, user-viewer, or user-other-company');if(!recipientId)return;const permission=prompt('Permission: view or edit','view');if(!permission)return;try{await api('/api/documents/'+id+'/shares',{method:'POST',body:JSON.stringify({recipientId,permission})});message('Share saved.');await load()}catch(e){message(e.message,true)}}
$('uploadForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/documents',{method:'POST',body:JSON.stringify({name:$('docName').value,contentType:$('contentType').value})});$('docName').value='';message('Document metadata created.');await load()}catch(err){message(err.message,true)}});
$('userSelect').addEventListener('change',load);$('refreshBtn').addEventListener('click',load);load();
</script></body></html>`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "127.0.0.1"}`);
  const pathname = url.pathname;
  const user = getRequestUser(url);

  if (req.method === "GET" && pathname === "/") {
    return sendHtml(res, html);
  }

  if (!user) {
    addAuditLog({
      actorId: "unknown",
      organizationId: null,
      action: "authentication",
      outcome: "denied",
      details: "Unknown demo user",
    });
    return sendJson(res, 401, { error: "Unknown demo user." });
  }

  if (req.method === "GET" && pathname === "/api/dashboard") {
    const visibleDocuments = documents.filter((document) => canReadDocument(user, document));
    const organization = organizations.find((item) => item.id === user.organizationId) || null;
    const logs = auditLogs
      .filter((log) => log.organizationId === user.organizationId)
      .map(({ id, actorId, action, documentId, outcome, details, timestamp }) => ({
        id, actorId, action, documentId, outcome, details, timestamp,
      }));

    return sendJson(res, 200, {
      user: { id: user.id, name: user.name, role: user.role },
      organization,
      documents: visibleDocuments.map(safeDocument),
      auditLogs: logs,
      visibleDocumentCount: visibleDocuments.length,
    });
  }

  if (req.method === "GET" && pathname === "/api/users") {
    const organizationUsers = users
      .filter((item) => item.organizationId === user.organizationId)
      .map(({ id, name, role }) => ({ id, name, role }));
    return sendJson(res, 200, { users: organizationUsers });
  }

  if (req.method === "POST" && pathname === "/api/documents") {
    let body;
    try {
      body = await readJson(req);
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }

    if (!["Admin", "Manager"].includes(user.role)) {
      addAuditLog({
        actorId: user.id,
        organizationId: user.organizationId,
        action: "document.create",
        outcome: "denied",
      });
      return sendJson(res, 403, { error: "Only Admins and Managers can create documents in this demo." });
    }

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const contentType = body.contentType;
    const allowedTypes = new Set([
      "application/pdf",
      "text/plain",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ]);

    if (!name || name.length > 120 || /[\\/]/.test(name) || !allowedTypes.has(contentType)) {
      return sendJson(res, 400, {
        error: "Provide a valid name (max 120 characters) and an allowed content type.",
      });
    }

    const document = {
      id: randomUUID(),
      organizationId: user.organizationId,
      ownerId: user.id,
      name,
      contentType,
      createdAt: nowIso(),
      shares: [],
    };
    documents.unshift(document);
    addAuditLog({
      actorId: user.id,
      organizationId: user.organizationId,
      action: "document.create",
      documentId: document.id,
      details: `Created metadata for ${document.name}`,
    });
    return sendJson(res, 201, { document: safeDocument(document) });
  }

  const shareMatch = pathname.match(/^\/api\/documents\/([^/]+)\/shares$/);
  if (req.method === "POST" && shareMatch) {
    let body;
    try {
      body = await readJson(req);
    } catch (error) {
      return sendJson(res, 400, { error: error.message });
    }

    const documentId = shareMatch[1];
    const document = findDocument(documentId);
    if (!document || !canManageDocument(user, document)) {
      addAuditLog({
        actorId: user.id,
        organizationId: user.organizationId,
        action: "document.share",
        documentId,
        outcome: "denied",
      });
      return sendJson(res, 404, { error: "Document not found or you cannot manage sharing." });
    }

    const recipient = typeof body.recipientId === "string" ? findUser(body.recipientId) : null;
    if (!recipient || recipient.organizationId !== document.organizationId) {
      addAuditLog({
        actorId: user.id,
        organizationId: user.organizationId,
        action: "document.share",
        documentId: document.id,
        outcome: "denied",
        details: "Cross-organization or unknown recipient",
      });
      return sendJson(res, 400, { error: "Recipient must belong to the same organization in this demo." });
    }

    if (!["view", "edit"].includes(body.permission)) {
      return sendJson(res, 400, { error: "Permission must be view or edit." });
    }

    const existingShare = document.shares.find((share) => share.userId === recipient.id);
    if (existingShare) existingShare.permission = body.permission;
    else document.shares.push({ userId: recipient.id, permission: body.permission });

    addAuditLog({
      actorId: user.id,
      organizationId: document.organizationId,
      action: "document.share",
      documentId: document.id,
      details: `Shared ${document.name} with ${recipient.id} (${body.permission})`,
    });
    return sendJson(res, 200, { document: safeDocument(document) });
  }

  const documentMatch = pathname.match(/^\/api\/documents\/([^/]+)$/);
  if (req.method === "GET" && documentMatch) {
    const documentId = documentMatch[1];
    const document = findDocument(documentId);
    if (!document || !canReadDocument(user, document)) {
      addAuditLog({
        actorId: user.id,
        organizationId: user.organizationId,
        action: "document.read",
        documentId: documentId,
        outcome: "denied",
        details: "Document not found or access denied",
      });
      return sendJson(res, 404, { error: "Document not found or access denied." });
    }

    addAuditLog({
      actorId: user.id,
      organizationId: document.organizationId,
      action: "document.read",
      documentId: document.id,
      details: `Read metadata for ${document.name}`,
    });
    return sendJson(res, 200, {
      document: safeDocument(document),
      note: "Demo metadata only; no file content is stored.",
    });
  }

  return sendJson(res, 404, { error: "Route not found." });
});

server.listen(PORT, HOST, () => {
  console.log(`TrustVault JavaScript demo running at http://${HOST}:${PORT}`);
  console.log("Demo identities are selected in the UI. This is not production authentication.");
});

server.on("error", (error) => {
  console.error("Could not start TrustVault:", error.message);
  process.exitCode = 1;
});
