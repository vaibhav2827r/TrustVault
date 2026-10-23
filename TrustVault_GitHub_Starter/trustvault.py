"""
TrustVault — secure document-sharing MVP (Python version)

Run:
    python trustvault.py

Then open http://localhost:3000

This is a demonstration scaffold for the Snovasys hiring assignment.
It uses in-memory demo data and MUST NOT be used for real confidential
documents. Restarting the server resets data. Before production, replace
the in-memory store with a database, real authentication, private object
storage, server-side authorization, and tamper-resistant audit logging.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 3000

organizations = [
    {"id": "org-acme", "name": "Acme Finance"},
    {"id": "org-northstar", "name": "Northstar Health"},
]

users = [
    {"id": "user-admin", "name": "Asha Admin", "organizationId": "org-acme", "role": "Admin"},
    {"id": "user-manager", "name": "Ravi Manager", "organizationId": "org-acme", "role": "Manager"},
    {"id": "user-viewer", "name": "Maya Viewer", "organizationId": "org-acme", "role": "Viewer"},
    {"id": "user-other-company", "name": "Noah OtherCo", "organizationId": "org-northstar", "role": "Admin"},
]

documents = [
    {
        "id": "doc-welcome",
        "organizationId": "org-acme",
        "ownerId": "user-admin",
        "name": "Welcome.pdf",
        "contentType": "application/pdf",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "shares": [{"userId": "user-viewer", "permission": "view"}],
    }
]

audit_logs = []


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_audit_log(actor_id, organization_id, action, document_id=None, outcome="success", details=""):
    # Demo only: this in-memory log is not tamper-proof.
    audit_logs.insert(0, {
        "id": str(uuid.uuid4()),
        "actorId": actor_id,
        "organizationId": organization_id,
        "action": action,
        "documentId": document_id,
        "outcome": outcome,
        "details": details,
        "timestamp": utc_now(),
    })


def can_read_document(user, document) -> bool:
    if not user or not document:
        return False
    same_org = user["organizationId"] == document["organizationId"]
    if same_org and (
        document["ownerId"] == user["id"]
        or user["role"] in ("Admin", "Manager")
    ):
        return True
    return any(
        share["userId"] == user["id"] and share["permission"] in ("view", "edit")
        for share in document["shares"]
    )


def can_manage_document(user, document) -> bool:
    return bool(
        user
        and document
        and user["organizationId"] == document["organizationId"]
        and (
            user["role"] == "Admin"
            or document["ownerId"] == user["id"]
            or user["role"] == "Manager"
        )
    )


def safe_document(document):
    return {
        "id": document["id"],
        "organizationId": document["organizationId"],
        "ownerId": document["ownerId"],
        "name": document["name"],
        "contentType": document["contentType"],
        "createdAt": document["createdAt"],
        "shares": document["shares"],
    }


def find_user(user_id):
    return next((user for user in users if user["id"] == user_id), None)


def find_document(document_id):
    return next((doc for doc in documents if doc["id"] == document_id), None)


def page_html():
    # A compact browser UI. The API enforces demo authorization checks.
    return r"""<!doctype html>
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
<p class="muted" style="margin-top:20px">Hiring-project prototype · Python standard library · No third-party packages</p>
</main>
<script>
const $=id=>document.getElementById(id), userId=()=>$('userSelect').value;
const esc=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,options={}){const sep=path.includes('?')?'&':'?';const r=await fetch(path+sep+'userId='+encodeURIComponent(userId()),{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
function message(t,bad=false){$('message').textContent=t;$('message').style.color=bad?'#b42318':'#187443'}
async function load(){try{const d=await api('/api/dashboard');$('docCount').textContent=d.documents.length;$('orgName').textContent=d.organization.name;$('auditCount').textContent=d.auditLogs.length;
$('documents').innerHTML=d.documents.length?d.documents.map(x=>`<div class="doc"><div><strong>📄 ${esc(x.name)}</strong><small>Owner: ${esc(x.ownerId)} · ${esc(new Date(x.createdAt).toLocaleString())}</small></div><div class="actions"><button class="secondary" onclick="viewDoc('${encodeURIComponent(x.id)}')">View</button><button class="secondary" onclick="shareDoc('${encodeURIComponent(x.id)}')">Share</button></div></div>`).join(''):'<p class="muted">No documents visible to this user.</p>';
$('auditLogs').innerHTML=d.auditLogs.length?d.auditLogs.slice(0,12).map(x=>`<div class="audit-row"><strong>${esc(x.action)} · ${esc(x.outcome)}</strong><span>${esc(x.actorId)} · ${esc(new Date(x.timestamp).toLocaleString())}</span><div class="muted">${esc(x.details||x.documentId||'')}</div></div>`).join(''):'<p class="muted">No audit events yet.</p>';
}catch(e){message(e.message,true)}}
async function viewDoc(id){try{const d=await api('/api/documents/'+id);message('Access granted to metadata for "'+d.document.name+'". No file content is stored in this demo.')}catch(e){message(e.message,true)}}
async function shareDoc(id){const recipientId=prompt('Share with user ID: user-admin, user-manager, user-viewer, or user-other-company');if(!recipientId)return;const permission=prompt('Permission: view or edit','view');if(!permission)return;try{await api('/api/documents/'+id+'/shares',{method:'POST',body:JSON.stringify({recipientId,permission})});message('Share saved.');await load()}catch(e){message(e.message,true)}}
$('uploadForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/documents',{method:'POST',body:JSON.stringify({name:$('docName').value,contentType:$('contentType').value})});$('docName').value='';message('Document metadata created.');await load()}catch(err){message(err.message,true)}});
$('userSelect').addEventListener('change',load);$('refreshBtn').addEventListener('click',load);load();
</script></body></html>"""


class TrustVaultHandler(BaseHTTPRequestHandler):
    server_version = "TrustVaultDemo/1.0"

    def log_message(self, fmt, *args):
        # Keep normal request logs in the terminal.
        super().log_message(fmt, *args)

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length < 0 or length > 1_000_000:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Invalid JSON body")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        user_id = query.get("userId", ["user-admin"])[0]
        user = find_user(user_id)

        if path == "/":
            return self.send_html(page_html())

        if not user:
            add_audit_log("unknown", None, "authentication", outcome="denied", details="Unknown demo user")
            return self.send_json(401, {"error": "Unknown demo user."})

        if path == "/api/dashboard":
            visible = [doc for doc in documents if can_read_document(user, doc)]
            org = next((item for item in organizations if item["id"] == user["organizationId"]), None)
            logs = [
                {key: value for key, value in log.items()
                 if key in {"id", "actorId", "action", "documentId", "outcome", "details", "timestamp"}}
                for log in audit_logs if log["organizationId"] == user["organizationId"]
            ]
            return self.send_json(200, {
                "user": {"id": user["id"], "name": user["name"], "role": user["role"]},
                "organization": org,
                "documents": [safe_document(doc) for doc in visible],
                "auditLogs": logs,
                "visibleDocumentCount": len(visible),
            })

        match = re.fullmatch(r"/api/documents/([^/]+)", path)
        if match:
            doc_id = match.group(1)
            doc = find_document(doc_id)
            if not doc or not can_read_document(user, doc):
                add_audit_log(user["id"], user["organizationId"], "document.read",
                              document_id=doc_id, outcome="denied",
                              details="Document not found or access denied")
                return self.send_json(404, {"error": "Document not found or access denied."})
            add_audit_log(user["id"], doc["organizationId"], "document.read",
                          document_id=doc["id"], details=f"Read metadata for {doc['name']}")
            return self.send_json(200, {
                "document": safe_document(doc),
                "note": "Demo metadata only; no file content is stored.",
            })

        if path == "/api/users":
            org_users = [
                {key: item[key] for key in ("id", "name", "role")}
                for item in users if item["organizationId"] == user["organizationId"]
            ]
            return self.send_json(200, {"users": org_users})

        return self.send_json(404, {"error": "Route not found."})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        user_id = query.get("userId", ["user-admin"])[0]
        user = find_user(user_id)
        if not user:
            add_audit_log("unknown", None, "authentication", outcome="denied", details="Unknown demo user")
            return self.send_json(401, {"error": "Unknown demo user."})

        try:
            body = self.read_json()
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})

        if path == "/api/documents":
            if user["role"] not in ("Admin", "Manager"):
                add_audit_log(user["id"], user["organizationId"], "document.create", outcome="denied")
                return self.send_json(403, {"error": "Only Admins and Managers can create documents in this demo."})
            name = body.get("name")
            content_type = body.get("contentType")
            allowed_types = {
                "application/pdf",
                "text/plain",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            }
            if (
                not isinstance(name, str)
                or not name.strip()
                or len(name.strip()) > 120
                or "/" in name
                or "\\" in name
                or content_type not in allowed_types
            ):
                return self.send_json(400, {
                    "error": "Provide a valid name (max 120 characters) and an allowed content type."
                })
            doc = {
                "id": str(uuid.uuid4()),
                "organizationId": user["organizationId"],
                "ownerId": user["id"],
                "name": name.strip(),
                "contentType": content_type,
                "createdAt": utc_now(),
                "shares": [],
            }
            documents.insert(0, doc)
            add_audit_log(user["id"], user["organizationId"], "document.create",
                          document_id=doc["id"], details=f"Created metadata for {doc['name']}")
            return self.send_json(201, {"document": safe_document(doc)})

        match = re.fullmatch(r"/api/documents/([^/]+)/shares", path)
        if match:
            doc_id = match.group(1)
            doc = find_document(doc_id)
            if not doc or not can_manage_document(user, doc):
                add_audit_log(user["id"], user["organizationId"], "document.share",
                              document_id=doc_id, outcome="denied")
                return self.send_json(404, {"error": "Document not found or you cannot manage sharing."})
            recipient_id = body.get("recipientId")
            permission = body.get("permission")
            recipient = find_user(recipient_id) if isinstance(recipient_id, str) else None
            if not recipient or recipient["organizationId"] != doc["organizationId"]:
                add_audit_log(user["id"], user["organizationId"], "document.share",
                              document_id=doc["id"], outcome="denied",
                              details="Cross-organization or unknown recipient")
                return self.send_json(400, {"error": "Recipient must belong to the same organization in this demo."})
            if permission not in ("view", "edit"):
                return self.send_json(400, {"error": "Permission must be view or edit."})
            existing = next((share for share in doc["shares"] if share["userId"] == recipient["id"]), None)
            if existing:
                existing["permission"] = permission
            else:
                doc["shares"].append({"userId": recipient["id"], "permission": permission})
            add_audit_log(user["id"], doc["organizationId"], "document.share",
                          document_id=doc["id"],
                          details=f"Shared {doc['name']} with {recipient['id']} ({permission})")
            return self.send_json(200, {"document": safe_document(doc)})

        return self.send_json(404, {"error": "Route not found."})


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), TrustVaultHandler)
    print(f"TrustVault Python demo running at http://{HOST}:{PORT}")
    print("Demo identities are selected in the UI. This is not production authentication.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nStopping TrustVault demo...")
    finally:
        server.server_close()
