// The AAuth call log (@aauth/call-log): one `aauth.call` record per call this
// service answers and per call it makes. Records go where every event goes,
// by the queue to Freezer, and the monitor shows them.
import type { Context } from 'hono'
import { callLogMiddleware, type CallLogHost } from '@aauth/call-log'
import { emit, emitBackground } from './events'
import type { Env, HonoEnv } from './types'

type Ctx = { waitUntil(p: Promise<unknown>): void } | undefined

const executionCtx = (c: Context<HonoEnv>): Ctx => {
  try {
    return c.executionCtx
  } catch {
    return undefined
  }
}

/** The host for a call this service answers: records carry the request context. */
export const calleeHost = (c: Context<HonoEnv>): CallLogHost => {
  const ctx = executionCtx(c)
  return {
    origin: c.env.ORIGIN,
    role: 'resource',
    log: (record) => emit(c, { ...record }),
    defer: ctx ? (p) => ctx.waitUntil(p) : undefined,
  }
}

/** The host for a call this service makes. */
export const callerHost = (env: Env, ctx: Ctx): CallLogHost => ({
  origin: env.ORIGIN,
  role: 'resource',
  log: (record) => emitBackground(env, ctx, { ...record }),
  defer: ctx ? (p) => ctx.waitUntil(p) : undefined,
})

export const callLog = async (c: Context<HonoEnv>, next: () => Promise<void>) => callLogMiddleware(calleeHost(c))(c, next)
