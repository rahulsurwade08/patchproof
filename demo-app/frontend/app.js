// DocuFlow frontend — calls backend API, demonstrates lodash/axios/marked usage
// OSV: lodash 4.17.20 <4.17.21 GHSA-4xc9-xhrj-v574 (prototype pollution), axios 1.15.0 <1.15.2 GHSA-3g43, marked 4.0.18 <4.0.10? actually 4.0.18 is >4.0.10 — pinned for demo scanner flag via OSV query
async function importYaml() {
  const body = document.getElementById('yamlInput').value;
  // lodash usage (vulnerable version flagged, but here on static string — not exploitable in this context; PatchProof would mark NOT_REACHABLE if it were a backend call site)
  const trimmed = _.trim(body);
  try {
    const r = await axios.post('/api/config/import', trimmed, { headers: { 'Content-Type': 'application/yaml' } });
    document.getElementById('yamlOut').textContent = JSON.stringify(r.data, null, 2);
  } catch (e) {
    document.getElementById('yamlOut').textContent = e.response ? JSON.stringify(e.response.data, null, 2) : String(e);
  }
}
async function render() {
  const template = document.getElementById('tmpl').value;
  let context = {};
  try { context = JSON.parse(document.getElementById('ctx').value); } catch {}
  // marked usage (client-side markdown — not server RCE; scanner flags it, PatchProof proves backend Jinja is the real reachable path)
  const preview = marked.parse(`**Preview:** ${_.escape(template)}`);
  document.getElementById('renderOut').innerHTML = preview;
  try {
    const r = await axios.post('/api/render', { template, context });
    document.getElementById('renderOut').textContent += "\n\n→ " + JSON.stringify(r.data, null, 2);
  } catch (e) {
    document.getElementById('renderOut').textContent += "\n" + String(e);
  }
}
async function createDoc(e) {
  e.preventDefault();
  const title = document.getElementById('docTitle').value;
  const body = document.getElementById('docBody').value;
  await axios.post('/api/documents', { title, body });
  listDocs();
}
async function listDocs() {
  const r = await axios.get('/api/documents');
  const ul = document.getElementById('docList');
  ul.innerHTML = '';
  for (const d of r.data.documents) {
    const li = document.createElement('li');
    li.textContent = `#${d.id} ${d.title}: ${d.body}`;
    ul.appendChild(li);
  }
}
async function exportDoc() {
  const id = document.getElementById('exportId').value;
  if (!id) return;
  const r = await axios.get(`/api/documents/${id}/export`);
  document.getElementById('exportOut').textContent = JSON.stringify(r.data, null, 2);
}
listDocs();
