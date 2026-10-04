const token = document.querySelector('meta[name="csrf-token"]').content;
const toast = document.querySelector('#toast');
const form = document.querySelector('#request-form');
const submitButton = form.querySelector('button[type="submit"]');
const sampleButton = document.querySelector('#sample-sequence');
let toastTimer;

function notify(message) {
  toast.textContent = message;
  toast.classList.add('is-visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 3600);
}

function escapeAsText(value) {
  return String(value ?? '—');
}

function updateBudget(mandate) {
  const spent = mandate.spent_minor;
  const total = mandate.total_budget_minor;
  const percent = total > 0 ? Math.min(100, Math.round((spent / total) * 100)) : 0;
  document.querySelector('#per-action').textContent = `${mandate.per_action_minor} DEMO`;
  document.querySelector('#total-cap').textContent = `${total} DEMO`;
  document.querySelector('#budget-label').textContent = `${spent} / ${total} · ${mandate.remaining_minor} left`;
  document.querySelector('#budget-progress').value = percent;
}

function createCell(tag, text, className = '') {
  const cell = document.createElement(tag);
  cell.textContent = escapeAsText(text);
  if (className) cell.className = className;
  return cell;
}

function renderReceipts(state) {
  const body = document.querySelector('#receipt-rows');
  const receipts = [...state.receipts].reverse();
  body.replaceChildren();
  document.querySelector('#receipt-count').textContent = `${state.audit.count} RECORD${state.audit.count === 1 ? '' : 'S'}`;
  document.querySelector('#audit-head').textContent = `HEAD ${state.audit.head.slice(0, 20)}…`;

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
    row.append(
      createCell('td', String(receipt.sequence).padStart(3, '0')),
      createCell('td', receipt.request_id),
    );
    const decisionCell = document.createElement('td');
    const chip = createCell('span', receipt.decision.toUpperCase(), `decision-chip ${receipt.decision}`);
    decisionCell.append(chip);
    row.append(decisionCell);
    row.append(
      createCell('td', `${receipt.amount_minor} DEMO`),
      createCell('td', receipt.executed ? 'YES' : 'NO'),
      createCell('td', receipt.hash.slice(0, 16), 'hash-cell'),
    );
    body.append(row);
  }
}

function renderState(state) {
  document.querySelector('#owner-id').textContent = state.identity.owner_id;
  document.querySelector('#agent-id').textContent = state.identity.agent_id;
  updateBudget(state.mandate);
  renderReceipts(state);
}

function renderResult(result, batch = false) {
  const decision = result.decision;
  const state = document.querySelector('#decision-state');
  state.className = `decision-state state-${decision}`;
  state.textContent = decision.toUpperCase();
  document.querySelector('#decision-title').textContent = batch ? 'Sample sequence complete' : 'Request evaluated';

  const descriptions = {
    allow: 'Within this demo mandate. The simulator records a budget reservation; no external operation executes.',
    escalate: 'The request crosses the review threshold. It remains pending; this demo has no human approval action.',
    block: 'The request is outside a scope or budget limit. A block consumes no simulated budget.',
  };
  const reasons = result.reasons.length ? ` Reasons: ${result.reasons.join(', ')}.` : '';
  const batchText = batch ? ' Demo decisions: allow → review → block.' : '';
  document.querySelector('#decision-summary').textContent = `${descriptions[decision]}${reasons}${batchText}`;

  const details = document.querySelector('#result-details');
  details.replaceChildren();
  const rows = [
    ['Request', result.request_id],
    ['Budget', `${result.amount_minor} DEMO`],
    ['Execution', result.executed ? 'Not reported' : 'NO · simulation'],
  ];
  for (const [label, value] of rows) {
    const group = document.createElement('div');
    group.append(createCell('dt', label), createCell('dd', value));
    details.append(group);
  }
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Autheo-Demo-Token': token,
    },
    body: JSON.stringify(payload),
    cache: 'no-store',
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

async function refreshState() {
  const response = await fetch('/api/state', { cache: 'no-store' });
  if (!response.ok) throw new Error(`State unavailable (${response.status})`);
  renderState(await response.json());
}

function setBusy(busy) {
  submitButton.disabled = busy;
  sampleButton.disabled = busy;
  submitButton.querySelector('span:first-child').textContent = busy ? 'Evaluating…' : 'Evaluate request';
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  setBusy(true);
  try {
    const payload = {
      action: document.querySelector('#action').value,
      resource: document.querySelector('#resource').value,
      amount_minor: Number(document.querySelector('#amount').value),
    };
    const response = await postJson('/api/simulate', payload);
    renderResult(response.results[0]);
    renderState(response.state);
  } catch (error) {
    notify(`Could not evaluate request: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

sampleButton.addEventListener('click', async () => {
  setBusy(true);
  try {
    const response = await postJson('/api/sample', {});
    renderResult(response.results.at(-1), true);
    renderState(response.state);
    notify('Sample sequence recorded: allow, review, block. Nothing was executed.');
  } catch (error) {
    notify(`Could not run sample: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

refreshState().catch((error) => notify(`Unable to load demo state: ${error.message}`));
