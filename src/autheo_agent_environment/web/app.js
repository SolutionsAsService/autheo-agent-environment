// Browser client for the local /v1 trust API (same origin, bearer token injected by the server).
const meta = (name) => document.querySelector(`meta[name="${name}"]`).content;
const token = meta('csrf-token');
const agentId = meta('autheo-agent-id');
const mandateId = meta('autheo-mandate-id');
const environmentId = meta('autheo-environment');
const toast = document.querySelector('#toast');
const form = document.querySelector('#request-form');
const submitButton = form.querySelector('button[type="submit"]');
const sampleButton = document.querySelector('#sample-sequence');
const verifyButton = document.querySelector('#verify-ledger');
const SAMPLE = [40, 55, 81];
let toastTimer;

function notify(message) {
  toast.textContent = message;
  toast.classList.add('is-visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 3600);
}

function createCell(tag, text, className = '') {
  const cell = document.createElement(tag);
  cell.textContent = String(text ?? '—');
  if (className) cell.className = className;
  return cell;
}

async function api(path, payload) {
  const options = {
    method: payload === undefined ? 'GET' : 'POST',
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  };
  if (payload !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail ? `${body.error}: ${body.detail}` : body.error || `HTTP ${response.status}`);
  return body;
}

function updateBudget(mandate) {
  const spent = mandate.spent_minor;
  const total = mandate.mandate.total_budget_minor;
  const percent = total > 0 ? Math.min(100, Math.round((spent / total) * 100)) : 0;
  document.querySelector('#per-action').textContent = `${mandate.mandate.per_action_minor} DEMO`;
  document.querySelector('#total-cap').textContent = `${total} DEMO`;
  document.querySelector('#budget-label').textContent = `${spent} / ${total} · ${mandate.remaining_minor} left`;
  document.querySelector('#budget-progress').value = percent;
}

function renderReceipts(ledger) {
  const body = document.querySelector('#receipt-rows');
  const receipts = ledger.receipts.map((item) => item.receipt).reverse();
  body.replaceChildren();
  document.querySelector('#receipt-count').textContent = `${ledger.count} RECORD${ledger.count === 1 ? '' : 'S'}`;
  document.querySelector('#audit-head').textContent = `HEAD ${ledger.head.slice(0, 20)}…`;
  if (!receipts.length) {
    const row = document.createElement('tr');
    row.className = 'empty-row';
    const cell = createCell('td', 'No requests recorded in this session.');
    cell.colSpan = 6;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const receipt of receipts) {
    const row = document.createElement('tr');
    row.append(createCell('td', String(receipt.sequence).padStart(3, '0')), createCell('td', receipt.request_id));
    const decisionCell = document.createElement('td');
    const label = receipt.kind === 'simulation' ? receipt.decision : `${receipt.kind.replace('_', ' ')}`;
    decisionCell.append(createCell('span', label.toUpperCase(), `decision-chip ${receipt.decision}`));
    row.append(decisionCell,
      createCell('td', `${receipt.amount_minor} DEMO`),
      createCell('td', receipt.executed ? 'YES' : 'NO'),
      createCell('td', receipt.hash.slice(0, 16), 'hash-cell'));
    body.append(row);
  }
}

async function refreshState() {
  const [identity, mandate, ledger] = await Promise.all([
    api(`/v1/identities/${encodeURIComponent(agentId)}`),
    api(`/v1/mandates/${encodeURIComponent(mandateId)}`),
    api(`/v1/ledger/receipts?environment=${encodeURIComponent(environmentId)}&limit=20`),
  ]);
  document.querySelector('#owner-id').textContent = identity.owner_id;
  document.querySelector('#agent-id').textContent = identity.agent_id;
  updateBudget(mandate);
  renderReceipts(ledger);
}

function renderResult(result, batch = false) {
  const decision = result.outcome;
  const state = document.querySelector('#decision-state');
  state.className = `decision-state state-${decision}`;
  state.textContent = decision.toUpperCase();
  document.querySelector('#decision-title').textContent = batch ? 'Sample sequence complete' : 'Request evaluated';
  const descriptions = {
    allow: 'Within this demo mandate and policy. The simulator records a budget reservation; no external operation executes.',
    escalate: 'The request needs human review. It remains pending; this demo has no approval action.',
    block: 'The request is outside a scope, policy or budget limit. A block consumes no simulated budget.',
  };
  const reasons = result.reasons.length ? ` Reasons: ${result.reasons.join(', ')}.` : '';
  const batchText = batch ? ' Demo decisions: allow → review → block.' : '';
  document.querySelector('#decision-summary').textContent = `${descriptions[decision]}${reasons}${batchText}`;
  const details = document.querySelector('#result-details');
  details.replaceChildren();
  for (const [label, value] of [
    ['Request', result.receipt.request_id],
    ['Budget', `${result.receipt.amount_minor} DEMO`],
    ['Execution', result.executed ? 'Not reported' : 'NO · simulation'],
  ]) {
    const group = document.createElement('div');
    group.append(createCell('dt', label), createCell('dd', value));
    details.append(group);
  }
  const list = document.querySelector('#explanation');
  list.replaceChildren();
  for (const check of result.decision?.explanation ?? []) {
    if (check.outcome === 'not_applicable') continue;
    const item = document.createElement('li');
    item.append(createCell('span', check.outcome.toUpperCase(), `check-${check.outcome}`), createCell('span', `${check.check} · ${check.detail}`));
    list.append(item);
  }
}

function evaluate(action, resource, amount) {
  return api('/v1/evaluate', { request: { agent_id: agentId, mandate_id: mandateId, action, resource, amount_minor: amount } });
}

function setBusy(busy) {
  submitButton.disabled = busy;
  sampleButton.disabled = busy;
  verifyButton.disabled = busy;
  submitButton.querySelector('span:first-child').textContent = busy ? 'Evaluating…' : 'Evaluate request';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  setBusy(true);
  try {
    const result = await evaluate(
      document.querySelector('#action').value,
      document.querySelector('#resource').value,
      Number(document.querySelector('#amount').value),
    );
    renderResult(result);
    await refreshState();
  } catch (error) {
    notify(`Could not evaluate request: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

sampleButton.addEventListener('click', async () => {
  setBusy(true);
  try {
    let last;
    for (const amount of SAMPLE) last = await evaluate('compute.simulate', 'listing:demo-01', amount);
    renderResult(last, true);
    await refreshState();
    notify('Sample sequence recorded: allow, review, block. Nothing was executed.');
  } catch (error) {
    notify(`Could not run sample: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

verifyButton.addEventListener('click', async () => {
  try {
    const report = await api(`/v1/ledger/verify?environment=${encodeURIComponent(environmentId)}`);
    notify(report.valid
      ? `Ledger verified: ${report.count} signed receipts, chain intact. Local only — not externally anchored.`
      : `Ledger verification FAILED at sequence ${report.first_invalid_sequence}.`);
  } catch (error) {
    notify(`Could not verify ledger: ${error.message}`);
  }
});

refreshState().catch((error) => notify(`Unable to load demo state: ${error.message}`));
