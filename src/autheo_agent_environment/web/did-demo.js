// Permissionless delegation demo: a root human DID delegates to an agent, which sub-delegates to a
// sub-agent with narrower rights; actions are allowed/blocked by the chain; a revocation takes effect;
// and the resulting decision bundles are verified IN THIS BROWSER with autheo-did.mjs (WebCrypto),
// pinned only to the human's DID and the environment DID - no server involved in verification.
import { verifyBundle } from '/assets/autheo-did.mjs';

const token = document.querySelector('meta[name="csrf-token"]').content;
const environmentId = document.querySelector('meta[name="autheo-environment"]').content;
const runButton = document.querySelector('#did-run');
const verifyButton = document.querySelector('#did-verify');
const steps = document.querySelector('#did-steps');
const chainView = document.querySelector('#did-chain');
const verifyView = document.querySelector('#did-verify-output');
let scenario = null;

async function api(path, payload) {
  const options = { method: payload === undefined ? 'GET' : 'POST', cache: 'no-store',
    headers: { Authorization: 'Bearer ' + token } };
  if (payload !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const body = await response.json();
  return { ok: response.ok, status: response.status, body };
}

async function must(path, payload) {
  const result = await api(path, payload);
  if (!result.ok) throw new Error((result.body.error || 'error') + ': ' + (result.body.detail || result.status));
  return result.body;
}

const short = (did) => (did ? did.slice(0, 16) + '…' + did.slice(-6) : '—');

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function step(title, outcome, detail) {
  const item = element('li', undefined, 'did-step');
  const head = element('div', undefined, 'did-step-head');
  head.append(element('strong', title));
  if (outcome) head.append(element('span', outcome.toUpperCase(), 'decision-chip state-' + chipClass(outcome)));
  item.append(head);
  if (detail) item.append(element('small', detail, 'mono'));
  steps.append(item);
}

function chipClass(outcome) {
  if (['allow', 'verified', 'valid', 'signed', 'trusted', 'created', 'recorded'].includes(outcome)) return 'allow';
  if (['escalate'].includes(outcome)) return 'escalate';
  if (['block', 'refused', 'invalid', 'revoked'].includes(outcome)) return 'block';
  return 'idle';
}

function renderChain(dids, chain) {
  chainView.replaceChildren();
  const names = { [dids.human]: 'Human (root)', [dids.agent]: 'Agent', [dids.sub]: 'Sub-agent' };
  chain.forEach((link, index) => {
    const cap = link.credentialSubject.capability;
    const card = element('div', undefined, 'did-link');
    card.append(element('span', 'LINK ' + index, 'eyebrow'));
    card.append(element('strong', names[link.issuer] + ' → ' + names[link.credentialSubject.id]));
    card.append(element('small', 'scopes: ' + cap.scopes.join(', ')));
    card.append(element('small', 'resources: ' + cap.resources.join(', ') + ' · envs: ' + cap.environments.join(', ')));
    card.append(element('small', 'per action ' + cap.per_action_minor + ' · total ' + cap.total_budget_minor
      + ' · review above ' + cap.approval_threshold_minor + ' · may delegate ' + cap.max_delegation_depth + ' more'));
    card.append(element('small', 'until ' + link.validUntil + ' · signed by ' + short(link.issuer), 'mono'));
    chainView.append(card);
  });
}

async function run() {
  runButton.disabled = true;
  verifyButton.disabled = true;
  steps.replaceChildren();
  verifyView.replaceChildren();
  try {
    const [human, agent, sub] = [(await must('/v1/dids', {})).did, (await must('/v1/dids', {})).did,
      (await must('/v1/dids', {})).did];
    const dids = { human, agent, sub };
    step('Three did:key identities created locally - no registry, no issuer', 'created',
      'human ' + short(human) + ' · agent ' + short(agent) + ' · sub-agent ' + short(sub));
    await must('/v1/trust-roots', { environment: environmentId, did: human });
    step('Environment ' + environmentId + ' pins the human DID as its root of authority', 'trusted', human);
    const rootCap = { environments: ['env:*'], scopes: ['compute.simulate', 'marketplace.read'],
      resources: ['listing:*'], per_action_minor: 80, total_budget_minor: 100, approval_threshold_minor: 50,
      max_delegation_depth: 1 };
    const first = await must('/v1/delegations', { issuer: human, subject: agent, capability: rootCap, ttl_seconds: 3600 });
    step('Human delegates to the agent (signed VC, eddsa-jcs-2022)', 'signed',
      'compute.simulate + marketplace.read on listing:* · 80/100 DEMO · may sub-delegate once');
    const subCap = { environments: [environmentId], scopes: ['compute.simulate'], resources: ['listing:demo-01'],
      per_action_minor: 30, total_budget_minor: 50, approval_threshold_minor: 20, max_delegation_depth: 0 };
    const second = await must('/v1/delegations', { issuer: agent, subject: sub, capability: subCap,
      parent_chain: first.chain, ttl_seconds: 1800 });
    const chain = second.chain;
    step('Agent sub-delegates a NARROWER capability to the sub-agent', 'signed',
      'compute.simulate on listing:demo-01 only · 30/50 DEMO · no further delegation');
    renderChain(dids, chain);
    const widened = await api('/v1/delegations', { issuer: agent, subject: sub, parent_chain: first.chain,
      capability: { ...subCap, scopes: ['compute.simulate', 'chain.read'] } });
    step('Agent tries to grant chain.read, which it never had', widened.ok ? 'signed' : 'refused',
      widened.ok ? 'unexpected' : 'not an attenuation of the parent - a verifier would reject it anyway');

    const act = (action, amount, id) => must('/v1/invocations/evaluate', { request: { invoker: sub, chain,
      environment: environmentId, action, resource: 'listing:demo-01', amount_minor: amount, request_id: id } });
    const suffix = Date.now().toString(36);
    const allowed = await act('compute.simulate', 20, 'req:did-allow-' + suffix);
    step('Sub-agent: compute.simulate 20 DEMO on listing:demo-01', allowed.outcome, allowed.reasons.join(', '));
    const blocked = await act('marketplace.read', 0, 'req:did-scope-' + suffix);
    step('Sub-agent: marketplace.read (the agent has it, the sub-agent does not)', blocked.outcome,
      blocked.reasons.join(', '));
    const revocation = await must('/v1/revocations', { issuer: agent, chain, reason: 'demo_revocation' });
    step('Agent revokes its delegation to the sub-agent (signed revocation record)', 'revoked',
      revocation.revocation.id);
    const afterRevoke = await act('compute.simulate', 20, 'req:did-revoked-' + suffix);
    step('Sub-agent repeats the allowed action after revocation', afterRevoke.outcome, afterRevoke.reasons.join(', '));
    const info = await must('/v1/info');
    scenario = { dids, info, bundles: { allowed: allowed.bundle, blocked: blocked.bundle, revoked: afterRevoke.bundle },
      revocations: [revocation.revocation] };
    verifyButton.disabled = false;
  } catch (error) {
    step('Scenario failed', 'invalid', error.message);
  } finally {
    runButton.disabled = false;
  }
}

async function verifyLocally() {
  if (!scenario) return;
  verifyView.replaceChildren();
  const options = { trustedRoots: [scenario.dids.human], environmentDid: scenario.info.authority_did };
  const show = (label, report, how) => {
    const row = element('div', undefined, 'did-verify-row');
    row.append(element('strong', label));
    row.append(element('span', report.valid ? report.verdict.replace('_', ' ').toUpperCase() : 'INVALID',
      'decision-chip state-' + (report.valid ? 'allow' : 'block')));
    const detail = report.valid
      ? (report.chain ? report.chain.links.length + ' links to root ' + short(report.root) : '') + ' · ' + how
      : (report.problems || []).join(', ');
    row.append(element('small', detail, 'mono'));
    verifyView.append(row);
  };
  let how = 'verified in this browser (WebCrypto Ed25519), no network';
  const verify = async (bundle, extra = {}) => {
    try {
      return await verifyBundle(bundle, { ...options, ...extra });
    } catch (error) {
      how = 'browser lacks Ed25519 WebCrypto - verified by the local API instead';
      return (await must('/v1/bundles/verify', { bundle, trusted_roots: options.trustedRoots,
        environment_did: options.environmentDid, revocations: extra.revocations || [] }));
    }
  };
  show('Allowed decision', await verify(scenario.bundles.allowed, { revocations: scenario.revocations }), how);
  show('Scope block', await verify(scenario.bundles.blocked), how);
  show('Post-revocation block', await verify(scenario.bundles.revoked), how);
  const forged = JSON.parse(JSON.stringify(scenario.bundles.revoked));
  forged.receipt.decision = 'allow';
  show('Forged: block receipt edited to allow', await verify(forged), how);
  const stranger = { ...options, trustedRoots: [scenario.dids.sub] };
  show('Allowed decision, pinned to the WRONG root', await verifyBundle(scenario.bundles.allowed, stranger)
    .catch(() => ({ valid: false, problems: ['unsupported'] })), how);
}

runButton.addEventListener('click', run);
verifyButton.addEventListener('click', verifyLocally);
