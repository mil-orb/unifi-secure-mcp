import { randomUUID } from 'node:crypto';
import { operations, byId, validateInput, activeSpec } from './catalog.mjs';
import { hash, secretFields } from './security.mjs';
import { authorize, record, lock, sharePreview, removePreview } from './permits.mjs';
export class Plans {
  constructor(
    config,
    client,
    {
      now = Date.now,
      auth = (o, i, plan) => authorize(config, o, i, plan),
      audit = (e) => record(config, e),
      acquire = () => lock(config),
      share = (preview) => sharePreview(config, preview),
      unshare = (id) => removePreview(config, id),
    } = {},
  ) {
    Object.assign(this, { config, client, now, auth, audit, acquire, share, unshare });
    this.plans = new Map();
    this.busy = false;
  }
  readOperation(op) {
    return operations.find((o) => o.readOnly && o.path === op.path);
  }
  readInput(op, input) {
    return {
      path: input.path,
      ...(op.inputSchema.properties.query
        ? {
            query: Object.fromEntries(
              Object.entries(input.query || {}).filter(([k]) =>
                Object.hasOwn(op.inputSchema.properties.query.properties, k),
              ),
            ),
          }
        : {}),
    };
  }
  async preview(op, input) {
    validateInput(op, input);
    if (op.readOnly) throw new Error('INPUT_INVALID');
    const readOp = this.readOperation(op);
    let before;
    if (readOp)
      before = await this.client.call(readOp, this.readInput(readOp, input), { raw: true });
    // Secret references are resolved to validate the exact request, but plans retain
    // only references. Changing a stored secret invalidates the preview.
    const resolved = this.client.resolveInput(input);
    validateInput(op, resolved);
    for (const [id, p] of this.plans) if (p.expires <= this.now()) this.plans.delete(id);
    if (this.plans.size >= 20) this.plans.delete(this.plans.keys().next().value);
    const id = randomUUID(),
      expires = this.now() + 300000;
    this.plans.set(id, {
      operation: op.id,
      input: structuredClone(input),
      bodyHash: hash(resolved),
      baseline: readOp ? hash(before) : null,
      expires,
    });
    const shown = this.client.clean({
      planId: id,
      operation: op.id,
      method: op.method,
      path: op.path,
      request: input,
      sensitiveFields: secretFields(input.body, readOp ? before : undefined),
      before: readOp ? before : undefined,
      expiresAt: new Date(expires).toISOString(),
      confirmation: `APPLY ${id}`,
      risk:
        op.method === 'DELETE'
          ? 'May permanently remove configuration or device adoption.'
          : 'May disrupt connectivity, change security, or affect attached devices.',
      precondition: readOp
        ? 'Current target will be re-read and compared before execution.'
        : 'This action has no matching GET snapshot; the preview cannot guarantee unchanged state.',
      rollback:
        'No automatic rollback is promised. Some operations are irreversible; prepare an operation-specific recovery plan.',
    });
    // Best effort: lets the user grant a permit for exactly this request locally.
    if (!this.config.configured || !this.config.writeEnabled) return shown;
    try {
      this.share({
        planId: id,
        operation: op.id,
        method: op.method,
        path: op.path,
        siteId: input.path?.siteId,
        request: shown.request,
        sensitiveFields: shown.sensitiveFields,
        requestHash: hash(resolved),
        expiresAt: shown.expiresAt,
        specVersion: activeSpec.loaded,
      });
      return { ...shown, localPermit: `unifi-secure-mcp permit --plan ${id}` };
    } catch {
      return shown;
    }
  }
  discard(id) {
    this.unshare(id);
    return { discarded: this.plans.delete(id) };
  }
  async apply(id, confirmation) {
    const p = this.plans.get(id);
    if (!p || p.expires <= this.now()) {
      this.plans.delete(id);
      throw new Error('PLAN_EXPIRED');
    }
    if (confirmation !== `APPLY ${id}`) throw new Error('PLAN_CONFIRMATION');
    const op = byId.get(p.operation);
    // Identifies this exact preview to a plan-bound permit (permit --plan).
    const binding = { id, requestHash: p.bodyHash };
    this.auth(op, p.input, binding);
    if (this.busy) throw new Error('WRITE_BUSY');
    const unlock = this.acquire();
    this.busy = true;
    this.plans.delete(id);
    this.unshare(id);
    let sent = false;
    const event = {
      planId: id,
      operation: op.id,
      siteId: p.input.path?.siteId,
      requestHash: p.bodyHash,
    };
    try {
      const readOp = this.readOperation(op);
      if (
        readOp &&
        hash(await this.client.call(readOp, this.readInput(readOp, p.input), { raw: true })) !==
          p.baseline
      )
        throw new Error('STALE_PLAN');
      const resolved = this.client.resolveInput(p.input);
      if (hash(resolved) !== p.bodyHash) throw new Error('STALE_PLAN');
      if (p.expires <= this.now()) throw new Error('PLAN_EXPIRED');
      this.auth(op, resolved, binding);
      this.audit({ ...event, outcome: 'attempt' });
      this.auth(op, resolved, binding);
      sent = true;
      const result = await this.client.call(op, resolved, { plan: binding });
      this.audit({ ...event, outcome: 'api-acknowledged' });
      return {
        planId: id,
        operation: op.id,
        outcome: 'api-acknowledged',
        result,
        verification:
          'The API acknowledged the request. Read the affected resource to verify eventual state; no automatic retry.',
      };
    } catch (e) {
      // The client marks failures that happened before any request byte left (notSent).
      const uncertain = sent && !e?.notSent;
      try {
        this.audit({ ...event, outcome: uncertain ? 'uncertain' : 'blocked' });
      } catch {}
      if (uncertain) throw new Error('WRITE_UNCERTAIN');
      throw e;
    } finally {
      this.busy = false;
      unlock();
    }
  }
}
