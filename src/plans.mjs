import { randomUUID } from 'node:crypto';
import { operations, byId, validateInput } from './catalog.mjs';
import { hash } from './security.mjs';
import { authorize, record, lock } from './permits.mjs';
export class Plans {
  constructor(
    config,
    client,
    {
      now = Date.now,
      auth = (o, i) => authorize(config, o, i),
      audit = (e) => record(config, e),
      acquire = () => lock(config),
    } = {},
  ) {
    Object.assign(this, { config, client, now, auth, audit, acquire });
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
    return this.client.clean({
      planId: id,
      operation: op.id,
      method: op.method,
      path: op.path,
      request: input,
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
  }
  discard(id) {
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
    this.auth(op, p.input);
    if (this.busy) throw new Error('WRITE_BUSY');
    const unlock = this.acquire();
    this.busy = true;
    this.plans.delete(id);
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
      this.auth(op, resolved);
      this.audit({ ...event, outcome: 'attempt' });
      this.auth(op, resolved);
      sent = true;
      const result = await this.client.call(op, resolved);
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
      try {
        this.audit({ ...event, outcome: sent ? 'uncertain' : 'blocked' });
      } catch {}
      if (sent) throw new Error('WRITE_UNCERTAIN');
      throw e;
    } finally {
      this.busy = false;
      unlock();
    }
  }
}
