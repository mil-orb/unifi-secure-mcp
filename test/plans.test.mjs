import test from 'node:test';
import assert from 'node:assert/strict';
import { Plans } from '../src/plans.mjs';
import { byId } from '../src/catalog.mjs';
const id = '00000000-0000-4000-8000-000000000001',
  op = byId.get('updateNetwork'),
  input = {
    path: { siteId: id, networkId: id },
    body: { management: 'UNMANAGED', name: 'Lab', enabled: false, vlanId: 20 },
  };
function harness(options = {}) {
  let state = { name: 'Before' },
    writes = 0,
    enabled = true,
    time = Date.now();
  const events = [];
  const client = {
    clean: (x) => x,
    resolveInput: (x) => x,
    call: async (op) => {
      if (!op.readOnly) {
        writes++;
        if (options.writeFails) throw new Error('TIMEOUT');
        return { ok: true };
      }
      return structuredClone(state);
    },
  };
  const plans = new Plans({}, client, {
    now: () => time,
    auth: () => {
      if (!enabled) throw new Error('READ_ONLY');
    },
    audit: (e) => {
      if (options.auditFails) throw new Error('AUDIT_UNAVAILABLE');
      events.push(e.outcome);
    },
    acquire: () => () => {},
  });
  return {
    plans,
    events,
    get writes() {
      return writes;
    },
    change() {
      state.name = 'Other';
    },
    disable() {
      enabled = false;
    },
    expire() {
      time += 300001;
    },
  };
}
test('preview is read-only and apply is exact, audited, single-use', async () => {
  const h = harness(),
    p = await h.plans.preview(op, input);
  assert.equal(h.writes, 0);
  await h.plans.apply(p.planId, p.confirmation);
  assert.equal(h.writes, 1);
  assert.deepEqual(h.events, ['attempt', 'api-acknowledged']);
  await assert.rejects(h.plans.apply(p.planId, p.confirmation), /PLAN_EXPIRED/);
});
test('expired, stale, disabled and unconfirmed plans never write', async () => {
  for (const mode of ['expire', 'change', 'disable', 'wrong']) {
    const h = harness(),
      p = await h.plans.preview(op, input);
    if (mode !== 'wrong') h[mode]();
    await assert.rejects(h.plans.apply(p.planId, mode === 'wrong' ? 'wrong' : p.confirmation));
    assert.equal(h.writes, 0);
  }
});
test('audit failure is fail-closed and concurrent apply cannot replay', async () => {
  const h = harness({ auditFails: true }),
    p = await h.plans.preview(op, input);
  await assert.rejects(h.plans.apply(p.planId, p.confirmation), /AUDIT_UNAVAILABLE/);
  assert.equal(h.writes, 0);
  const q = harness(),
    r = await q.plans.preview(op, input);
  const results = await Promise.allSettled([
    q.plans.apply(r.planId, r.confirmation),
    q.plans.apply(r.planId, r.confirmation),
  ]);
  assert.equal(results.filter((x) => x.status === 'fulfilled').length, 1);
  assert.equal(q.writes, 1);
});
test('uncertain writes are consumed, audited and never automatically retried', async () => {
  const h = harness({ writeFails: true }),
    p = await h.plans.preview(op, input);
  await assert.rejects(h.plans.apply(p.planId, p.confirmation), /WRITE_UNCERTAIN/);
  await assert.rejects(h.plans.apply(p.planId, p.confirmation), /PLAN_EXPIRED/);
  assert.equal(h.writes, 1);
  assert.deepEqual(h.events, ['attempt', 'uncertain']);
});
