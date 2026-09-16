// Structured events in the shape registry / aauth-mcp / aauth-proxy ship to
// Freezer: snake_case service/event/timestamp/level/event_id, then request
// context, then fields. Events go to console (Workers Logs); when
// EVENTS_QUEUE is bound (plan item T) they also go to the queue. Identity on events is person_id, never an
// address (A8). Copied from decrypt/src/events.ts.
import type { Context } from 'hono'
import type { Env, HonoEnv } from './types'

export type EmitInput = {
  event: string
  level?: number
  msg?: string
  [k: string]: unknown
}

function base(env: Env, input: EmitInput) {
  return {
    service: env.SERVICE,
    timestamp: new Date().toISOString(),
    event_id: crypto.randomUUID(),
    level: 30,
    ...input,
  }
}

function requestContext(req: Request) {
  const h = req.headers
  return {
    method: req.method,
    route: new URL(req.url).pathname,
    cf_ray: h.get('cf-ray') ?? undefined,
    client_ip: h.get('cf-connecting-ip') ?? undefined,
    user_agent: h.get('user-agent') ?? undefined,
  }
}

function signatureHeaders(req: Request) {
  const h = req.headers
  return {
    sig_signature: h.get('signature') ?? undefined,
    sig_signature_input: h.get('signature-input') ?? undefined,
    sig_signature_key: h.get('signature-key') ?? undefined,
  }
}

function ship(env: Env, ctx: { waitUntil(p: Promise<unknown>): void } | undefined, full: Record<string, unknown>): void {
  console.log(JSON.stringify(full))
  if (env.EVENTS_QUEUE) {
    const p = env.EVENTS_QUEUE.send(full).catch((err: unknown) =>
      console.error(JSON.stringify({ event: 'event_emit_failed', error: String(err), original: full.event })),
    )
    if (ctx) ctx.waitUntil(p)
  }
}

export function emit(c: Context<HonoEnv>, input: EmitInput): void {
  let ctx: { waitUntil(p: Promise<unknown>): void } | undefined
  try {
    ctx = c.executionCtx
  } catch {
    ctx = undefined
  }
  ship(c.env, ctx, { ...base(c.env, input), ...requestContext(c.req.raw) })
}

export function emitBackground(env: Env, ctx: { waitUntil(p: Promise<unknown>): void } | undefined, input: EmitInput): void {
  ship(env, ctx, base(env, input))
}

export function emitVerifyFailed(c: Context<HonoEnv>, reason: string, extra: Record<string, unknown> = {}): void {
  emit(c, {
    event: 'verify_failed',
    level: 40,
    msg: `verify failed: ${reason}`,
    failure_reason: reason,
    ...signatureHeaders(c.req.raw),
    ...extra,
  })
}
