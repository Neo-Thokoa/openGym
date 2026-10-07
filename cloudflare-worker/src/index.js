import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'

const COOKIE = 'og_session'
const SESSION_DAYS = 30
const CHALLENGE_MS = 5 * 60_000
const DEVICE_LINK_MS = 10 * 60_000
const PAIR_MS = 5 * 60_000
const MAX_JSON_BYTES = 6 * 1024 * 1024
const MEDIA_QUOTA = 200 * 1024 * 1024
const MEDIA_CAPS = { image: 2 * 1024 * 1024, gif: 8 * 1024 * 1024, video: 40 * 1024 * 1024 }
const VIDEO_SECONDS = 60
const enc = new TextEncoder()
const dec = new TextDecoder()

const isObject = x => !!x && typeof x === 'object' && !Array.isArray(x)
const json = (status, body, extra = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra },
})
const error = (status, message, extra = {}, headersExtra = {}) => {
  const body = { error: message }
  const headers = {}
  for (const [key, value] of Object.entries(extra || {})) {
    if (key === 'X-Error-Code') body.code = value
    else if (key.startsWith('Access-Control-') || key === 'Vary' || key === 'Retry-After') headers[key] = value
    else body[key] = value
  }
  for (const [key, value] of Object.entries(headersExtra || {})) headers[key] = value
  return json(status, body, headers)
}
const utcNow = () => new Date().toISOString()
const b64u = bytes => {
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (let i = 0; i < a.length; i += 1) binary += String.fromCharCode(a[i])
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
const unb64u = text => {
  const s = String(text || '').replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(s + '='.repeat((4 - s.length % 4) % 4))
  return Uint8Array.from(binary, c => c.charCodeAt(0))
}
const randomId = (size = 18) => {
  const bytes = crypto.getRandomValues(new Uint8Array(size))
  return b64u(bytes)
}
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('')
const sha256 = async bytes => hex(await crypto.subtle.digest('SHA-256', bytes))
const shaText = text => sha256(enc.encode(text))
const signed = async (payload, secret) => {
  if (!secret || secret.length < 32) throw new Error('SESSION_SECRET must contain at least 32 characters')
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return b64u(await crypto.subtle.sign('HMAC', key, enc.encode(payload)))
}
const verifySig = async (payload, signature, secret) => {
  if (!secret || secret.length < 32) return false
  try {
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
    return crypto.subtle.verify('HMAC', key, unb64u(signature), enc.encode(payload))
  } catch { return false }
}

async function readJson(request) {
  const announced = Number(request.headers.get('content-length') || 0)
  if (announced > MAX_JSON_BYTES) throw Object.assign(new Error('request too large'), { status: 413 })
  const bytes = await request.arrayBuffer()
  if (bytes.byteLength > MAX_JSON_BYTES) throw Object.assign(new Error('request too large'), { status: 413 })
  try { return JSON.parse(dec.decode(bytes)) } catch { throw Object.assign(new Error('invalid JSON'), { status: 400 }) }
}

async function readBoundedBytes(request, limit) {
  const announced = Number(request.headers.get('content-length') || 0)
  if (announced > limit) throw Object.assign(new Error('payload too large'), { status: 413 })
  const reader = request.body?.getReader()
  if (!reader) return new Uint8Array(0)
  const chunks = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > limit) {
      try { await reader.cancel() } catch { /* connection may already be closed */ }
      throw Object.assign(new Error('payload too large'), { status: 413 })
    }
    chunks.push(value)
  }
  const output = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength }
  return output
}

function corsHeaders(request) {
  const origin = request.headers.get('origin')
  return {
    ...(origin ? { 'Access-Control-Allow-Origin': origin, Vary: 'Origin' } : {}),
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age': '86400',
  }
}
function needsOriginCheck(method, path) {
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return false
  return !['/api/register/options', '/api/register/verify', '/api/login/options', '/api/login/verify', '/api/device-link/options', '/api/device-link/verify', '/api/pair/redeem'].includes(path)
}
function originAllowed(request, env) {
  if ((request.headers.get('authorization') || '').startsWith('Bearer ')) return true
  const origin = request.headers.get('origin')
  return !origin || origin === env.APP_ORIGIN
}

async function storeChallenge(db, payload) {
  const id = randomId(16)
  const expires = Date.now() + CHALLENGE_MS
  await db.prepare('INSERT INTO challenges(id,payload,expires_at) VALUES(?,?,?)').bind(id, JSON.stringify(payload), expires).run()
  return id
}
async function consumeChallenge(db, id) {
  if (typeof id !== 'string' || !id) return null
  const row = await db.prepare('DELETE FROM challenges WHERE id=? AND expires_at>? RETURNING payload').bind(id, Date.now()).first()
  if (!row) return null
  try { return JSON.parse(row.payload) } catch { return null }
}

function cookieValue(request) {
  const header = request.headers.get('cookie') || ''
  for (const part of header.split(';')) {
    const i = part.indexOf('=')
    if (i >= 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim())
  }
  return null
}
async function makeToken(user, env) {
  const expiry = Date.now() + SESSION_DAYS * 86_400_000
  const payload = b64u(enc.encode(`${user.id}:${expiry}:${Number(user.session_version || 0)}`))
  return `${payload}.${await signed(payload, env.SESSION_SECRET)}`
}
function sessionCookie(token, env) {
  const secure = String(env.APP_ORIGIN || '').startsWith('https://') ? '; Secure' : ''
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`
}
const clearCookie = `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`
async function getSession(request, env) {
  const auth = request.headers.get('authorization') || ''
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : null
  const token = bearer || cookieValue(request)
  if (!token) return null
  const parts = token.split('.')
  if (parts.length !== 2 || !(await verifySig(parts[0], parts[1], env.SESSION_SECRET))) return null
  let parsed
  try { parsed = dec.decode(unb64u(parts[0])).split(':') } catch { return null }
  if (parsed.length !== 3) return null
  const [uid, expiryText, versionText] = parsed
  const expiry = Number(expiryText), version = Number(versionText)
  if (!uid || !Number.isFinite(expiry) || expiry <= Date.now() || !Number.isSafeInteger(version)) return null
  const user = await env.DB.prepare('SELECT id,name,created_at,session_version,disabled,admin,last_pull FROM users WHERE id=?').bind(uid).first()
  if (!user || user.disabled || Number(user.session_version) !== version) return null
  return { user, bearer: !!bearer, expiry, token }
}
const publicUser = user => ({ id: user.id, name: user.name, admin: !!user.admin })
async function authOr401(request, env) {
  const session = await getSession(request, env)
  return session || false
}

async function credentialsFor(db, uid) {
  return db.prepare('SELECT credential_id,public_key,counter,transports,display_name,created_at,last_used FROM passkeys WHERE user_id=? ORDER BY created_at').bind(uid).all()
}
function passkeyList(result) {
  return (result?.results || []).map(row => ({
    id: row.credential_id,
    name: row.display_name || '',
    created: row.created_at || null,
    lastUsed: row.last_used || null,
  }))
}
async function passkeyState(db, uid) {
  const list = passkeyList(await credentialsFor(db, uid))
  return { passkeys: list, password: false, lastWayIn: list.length <= 1 }
}
function credentialFromVerification(verification, body, userId, name) {
  const info = verification.registrationInfo
  const credential = info?.credential
  if (!credential?.id || !credential?.publicKey) return null
  return {
    id: credential.id,
    userId,
    publicKey: b64u(credential.publicKey),
    counter: credential.counter || 0,
    transports: JSON.stringify(body?.response?.transports || []),
    name: String(name || '').trim().slice(0, 40),
  }
}
function newCredentialParams(cred, created) {
  return [cred.id, cred.userId, cred.publicKey, cred.counter, cred.transports, cred.name || null, created, created]
}
async function createOptions(env, { userId, name, credentials = [] }) {
  const excludeCredentials = credentials.map(c => ({ id: c.credential_id, transports: safeJsonArray(c.transports) }))
  return generateRegistrationOptions({
    rpName: env.RP_NAME || 'openGym',
    rpID: env.RP_ID,
    userID: enc.encode(userId),
    userName: name,
    userDisplayName: name,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    excludeCredentials,
  })
}
function safeJsonArray(raw) { try { const x = JSON.parse(raw || '[]'); return Array.isArray(x) ? x : [] } catch { return [] } }

async function verifyRegistration(env, challenge, credential) {
  try {
    return await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: env.APP_ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: false,
    })
  } catch (e) {
    return { verified: false, reason: 'invalid-credential' }
  }
}
async function verifyOwnerProof(request, env, userId, proof) {
  if (!proof || typeof proof.cid !== 'string' || !proof.credential?.id) return { ok: false, status: 400, message: 'owner confirmation required' }
  const challenge = await consumeChallenge(env.DB, proof.cid)
  if (!challenge || challenge.kind !== 'login') return { ok: false, status: 400, message: 'challenge expired — try again' }
  const cred = await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id=? AND user_id=?').bind(proof.credential.id, userId).first()
  if (!cred) return { ok: false, status: 403, message: 'passkey could not be confirmed' }
  try {
    const verification = await verifyAuthenticationResponse({
      response: proof.credential,
      expectedChallenge: challenge.challenge,
      expectedOrigin: env.APP_ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: false,
      credential: {
        id: cred.credential_id,
        publicKey: unb64u(cred.public_key),
        counter: Number(cred.counter),
        transports: safeJsonArray(cred.transports),
      },
    })
    if (!verification.verified) return { ok: false, status: 403, message: 'passkey could not be confirmed' }
    await env.DB.prepare('UPDATE passkeys SET counter=?,last_used=? WHERE credential_id=?')
      .bind(verification.authenticationInfo.newCounter || 0, utcNow(), cred.credential_id).run()
    return { ok: true }
  } catch { return { ok: false, status: 403, message: 'passkey could not be confirmed' } }
}

function validProfileState(state) {
  if (!isObject(state) || !Object.keys(state).some(k => k !== '_rev' && k !== '_ts')) return false
  if (Array.isArray(state) || (state.workouts != null && !Array.isArray(state.workouts)) || (state.routines != null && !Array.isArray(state.routines))) return false
  return true
}
const records = list => list.filter(x => isObject(x))
function stateRefs(state) {
  const refs = new Set()
  const seen = new Set()
  const walk = value => {
    if (!value || typeof value !== 'object' || seen.has(value)) return
    seen.add(value)
    if (!Array.isArray(value) && typeof value.hash === 'string' && /^[a-f0-9]{64}$/i.test(value.hash)) refs.add(value.hash.toLowerCase())
    for (const child of Array.isArray(value) ? value : Object.values(value)) walk(child)
  }
  walk(state)
  return refs
}

function mp4Duration(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const read32 = p => p + 4 <= bytes.length ? view.getUint32(p) : null
  const read64 = p => p + 8 <= bytes.length ? Number(view.getBigUint64(p)) : null
  let offset = 0, boxes = 0
  while (offset + 8 <= bytes.length && boxes++ < 100_000) {
    let size = read32(offset)
    const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7])
    let header = 8
    if (size === 1) { size = read64(offset + 8); header = 16 }
    if (size === 0) size = bytes.length - offset
    if (!size || size < header || offset + size > bytes.length) return null
    if (type === 'moov') {
      let pos = offset + header
      const end = offset + size
      while (pos + 8 <= end) {
        let childSize = read32(pos)
        const childType = String.fromCharCode(bytes[pos + 4], bytes[pos + 5], bytes[pos + 6], bytes[pos + 7])
        let childHead = 8
        if (childSize === 1) { childSize = read64(pos + 8); childHead = 16 }
        if (!childSize || childSize < childHead || pos + childSize > end) break
        if (childType === 'mvhd') {
          const body = pos + childHead
          const version = bytes[body]
          const timescale = read32(body + (version === 1 ? 20 : 12))
          const duration = version === 1 ? read64(body + 24) : read32(body + 16)
          return timescale && duration != null ? duration / timescale : null
        }
        pos += childSize
      }
      return null
    }
    if (offset === 0 && type !== 'ftyp') return null
    offset += size
  }
  return null
}
function sniff(bytes) {
  const starts = (...a) => a.every((x, i) => bytes[i] === x)
  const ascii = (start, len) => String.fromCharCode(...bytes.slice(start, start + len))
  if (starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return { category: 'image', ext: 'png', mime: 'image/png' }
  if (starts(0xff, 0xd8, 0xff)) return { category: 'image', ext: 'jpg', mime: 'image/jpeg' }
  if (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a') return { category: 'gif', ext: 'gif', mime: 'image/gif' }
  if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return { category: 'image', ext: 'webp', mime: 'image/webp' }
  if (ascii(4, 4) === 'ftyp') {
    const brand = ascii(8, 4)
    return { category: 'video', ext: brand === 'qt  ' ? 'mov' : 'mp4', mime: brand === 'qt  ' ? 'video/quicktime' : 'video/mp4' }
  }
  if (starts(0x1a, 0x45, 0xdf, 0xa3)) return { category: 'video', ext: 'webm', mime: 'video/webm' }
  return null
}
function declaredCategory(mime) {
  const t = String(mime || '').split(';')[0].trim().toLowerCase()
  if (t === 'image/gif') return 'gif'
  if (t.startsWith('image/')) return 'image'
  if (t.startsWith('video/')) return 'video'
  return null
}
const MEDIA_MESSAGES = {
  'media-type': 'that file type is not accepted',
  'media-too-large': 'that file is too large',
  'media-quota': 'your space for photos and videos is full',
  'media-invalid': 'that video could not be read',
  'media-too-long': 'that video is too long',
  'media-missing': 'no such file',
  'hash-mismatch': 'the file does not match its name',
  'storage-full': 'media storage is temporarily unavailable',
}
function mediaError(status, code, extra = {}, headers = {}) {
  return error(status, MEDIA_MESSAGES[code] || code, { code, ...extra }, headers)
}

async function getMediaUsage(db, uid) {
  const row = await db.prepare('SELECT COALESCE(SUM(size),0) AS bytes,COUNT(*) AS count FROM media WHERE user_id=?').bind(uid).first()
  return { bytes: Number(row?.bytes || 0), count: Number(row?.count || 0), quotaBytes: MEDIA_QUOTA }
}

async function reconcileMedia(env, uid, state) {
  const refs = stateRefs(state)
  const rows = await env.DB.prepare('SELECT hash,unreferenced_at FROM media WHERE user_id=?').bind(uid).all()
  const now = Date.now()
  for (const row of rows.results || []) {
    if (refs.has(row.hash) && row.unreferenced_at != null) {
      await env.DB.prepare('UPDATE media SET unreferenced_at=NULL WHERE user_id=? AND hash=?').bind(uid, row.hash).run()
    } else if (!refs.has(row.hash) && row.unreferenced_at == null) {
      await env.DB.prepare('UPDATE media SET unreferenced_at=? WHERE user_id=? AND hash=?').bind(now, uid, row.hash).run()
    }
  }
}

async function collectUnreferenced(env, uid, graceMs) {
  const cutoff = Date.now() - graceMs
  const rows = await env.DB.prepare('SELECT hash,object_key,size FROM media WHERE user_id=? AND unreferenced_at IS NOT NULL AND unreferenced_at<=?').bind(uid, cutoff).all()
  let removed = 0, freedBytes = 0
  for (const row of rows.results || []) {
    await env.MEDIA.delete(row.object_key)
    await env.DB.prepare('DELETE FROM media WHERE user_id=? AND hash=?').bind(uid, row.hash).run()
    removed += 1
    freedBytes += Number(row.size || 0)
  }
  return { removed, freedBytes }
}

export async function handleRequest(request, env) {
  const url = new URL(request.url)
  const path = url.pathname
  const method = request.method.toUpperCase()
  const cors = corsHeaders(request)
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: cors })
  if (!env.DB) return error(503, 'database binding is unavailable', cors)
  if (needsOriginCheck(method, path) && !originAllowed(request, env)) return error(403, 'origin not allowed', cors)

  try {
    if (method === 'GET' && path === '/api/health') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first()
      return json(200, { ok: true, users: Number(row?.n || 0) }, cors)
    }
    if (method === 'GET' && path === '/api/config') {
      return json(200, {
        invite_only: false,
        allow_guest: true,
        media: { imageMB: 2, gifMB: 8, videoMB: 40, videoSec: VIDEO_SECONDS, quotaMB: 200, workouts: true },
      }, cors)
    }
    if (method === 'GET' && path === '/api/me') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const renew = session.bearer && session.expiry - Date.now() < SESSION_DAYS * 86_400_000 / 2
      return json(200, { user: publicUser(session.user), ...(renew ? { token: await makeToken(session.user, env) } : {}) }, cors)
    }

    if (method === 'POST' && path === '/api/register/options') {
      const body = await readJson(request)
      const name = String(body.name || '').normalize('NFKC').trim().slice(0, 40)
      if (!name) return error(400, 'name required', cors)
      const uid = randomId(12)
      const options = await createOptions(env, { userId: uid, name })
      const cid = await storeChallenge(env.DB, { kind: 'register', challenge: options.challenge, uid, name })
      return json(200, { cid, options }, cors)
    }
    if (method === 'POST' && path === '/api/register/verify') {
      const body = await readJson(request)
      const challenge = await consumeChallenge(env.DB, body.cid)
      if (!challenge || challenge.kind !== 'register' || !challenge.uid) return error(400, 'challenge expired — try again', cors)
      const verification = await verifyRegistration(env, challenge.challenge, body.credential)
      if (!verification.verified) return error(400, 'passkey could not be verified', cors)
      const cred = credentialFromVerification(verification, body.credential, challenge.uid, '')
      if (!cred) return error(400, 'invalid passkey response', cors)
      const exists = await env.DB.prepare('SELECT 1 FROM passkeys WHERE credential_id=?').bind(cred.id).first()
      if (exists) return error(409, 'credential already registered', { ...cors, 'X-Error-Code': 'credential-exists' })
      const created = utcNow()
      try {
        await env.DB.batch([
          env.DB.prepare('INSERT INTO users(id,name,created_at) VALUES(?,?,?)').bind(challenge.uid, challenge.name, created),
          env.DB.prepare('INSERT INTO passkeys(credential_id,user_id,public_key,counter,transports,display_name,created_at,last_used) VALUES(?,?,?,?,?,?,?,?)').bind(...newCredentialParams(cred, created)),
        ])
      } catch (e) {
        return error(409, 'credential already registered', cors)
      }
      const user = { id: challenge.uid, name: challenge.name, admin: false, session_version: 0 }
      const token = await makeToken(user, env)
      return json(200, { user: publicUser(user) }, { ...cors, 'Set-Cookie': sessionCookie(token, env) })
    }

    if (method === 'POST' && path === '/api/login/options') {
      const options = await generateAuthenticationOptions({ rpID: env.RP_ID, userVerification: 'preferred', allowCredentials: [] })
      const cid = await storeChallenge(env.DB, { kind: 'login', challenge: options.challenge })
      return json(200, { cid, options }, cors)
    }
    if (method === 'POST' && path === '/api/login/verify') {
      const body = await readJson(request)
      const challenge = await consumeChallenge(env.DB, body.cid)
      if (!challenge || challenge.kind !== 'login') return error(400, 'challenge expired — try again', cors)
      const id = body.credential?.id
      const cred = typeof id === 'string' ? await env.DB.prepare('SELECT * FROM passkeys WHERE credential_id=?').bind(id).first() : null
      if (!cred) return error(404, 'unknown passkey — create a profile first', cors)
      const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(cred.user_id).first()
      if (!user) return error(500, 'user missing', cors)
      if (user.disabled) return error(403, 'this account has been disabled', cors)
      try {
        const verification = await verifyAuthenticationResponse({
          response: body.credential,
          expectedChallenge: challenge.challenge,
          expectedOrigin: env.APP_ORIGIN,
          expectedRPID: env.RP_ID,
          requireUserVerification: false,
          credential: { id: cred.credential_id, publicKey: unb64u(cred.public_key), counter: Number(cred.counter), transports: safeJsonArray(cred.transports) },
        })
        if (!verification.verified) return error(400, 'not verified', cors)
        await env.DB.prepare('UPDATE passkeys SET counter=?,last_used=? WHERE credential_id=?').bind(verification.authenticationInfo.newCounter || 0, utcNow(), cred.credential_id).run()
      } catch { return error(400, 'passkey could not be verified', cors) }
      const token = await makeToken(user, env)
      return json(200, { user: publicUser(user) }, { ...cors, 'Set-Cookie': sessionCookie(token, env) })
    }
    if (method === 'POST' && path === '/api/logout') return json(200, { ok: true }, { ...cors, 'Set-Cookie': clearCookie })
    if (method === 'POST' && path === '/api/logout/all') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      await env.DB.prepare('UPDATE users SET session_version=session_version+1 WHERE id=?').bind(session.user.id).run()
      await env.DB.batch([
        env.DB.prepare('DELETE FROM device_link_codes WHERE user_id=?').bind(session.user.id),
        env.DB.prepare('DELETE FROM pair_codes WHERE user_id=?').bind(session.user.id),
      ])
      return json(200, { ok: true }, { ...cors, 'Set-Cookie': clearCookie })
    }

    if (method === 'GET' && path === '/api/account/passkeys') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      return json(200, await passkeyState(env.DB, session.user.id), cors)
    }
    if (method === 'POST' && path === '/api/account/passkeys/options') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      const proof = await verifyOwnerProof(request, env, session.user.id, body)
      if (!proof.ok) return error(proof.status, proof.message, cors)
      const credentials = await credentialsFor(env.DB, session.user.id)
      if ((credentials.results || []).length >= 20) return error(409, 'a profile can have at most 20 passkeys', { ...cors, 'X-Error-Code': 'passkey-limit' })
      const options = await createOptions(env, { userId: session.user.id, name: session.user.name, credentials: credentials.results || [] })
      const cid = await storeChallenge(env.DB, { kind: 'add', challenge: options.challenge, uid: session.user.id, sv: session.user.session_version })
      return json(200, { cid, options }, cors)
    }
    if (method === 'POST' && path === '/api/account/passkeys/verify') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      const challenge = await consumeChallenge(env.DB, body.cid)
      if (!challenge || challenge.kind !== 'add' || challenge.uid !== session.user.id || Number(challenge.sv) !== Number(session.user.session_version)) return error(400, 'challenge expired — try again', cors)
      const verification = await verifyRegistration(env, challenge.challenge, body.credential)
      if (!verification.verified) return error(400, 'passkey could not be verified', cors)
      const cred = credentialFromVerification(verification, body.credential, session.user.id, body.name)
      if (!cred) return error(400, 'invalid passkey response', cors)
      try {
        const created = utcNow()
        await env.DB.prepare('INSERT INTO passkeys(credential_id,user_id,public_key,counter,transports,display_name,created_at,last_used) VALUES(?,?,?,?,?,?,?,?)').bind(...newCredentialParams(cred, created)).run()
      } catch { return error(409, 'this passkey already belongs to a profile', { ...cors, 'X-Error-Code': 'credential-exists' }) }
      return json(200, { ok: true, ...await passkeyState(env.DB, session.user.id) }, cors)
    }
    if (method === 'POST' && path === '/api/account/passkeys/rename') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      const name = String(body.name || '').trim().slice(0, 40)
      const result = await env.DB.prepare('UPDATE passkeys SET display_name=? WHERE credential_id=? AND user_id=?').bind(name || null, body.id, session.user.id).run()
      if (!result.meta?.changes) return error(404, 'passkey not found', cors)
      return json(200, { ok: true, ...await passkeyState(env.DB, session.user.id) }, cors)
    }
    if (method === 'DELETE' && path === '/api/account/passkeys') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const id = url.searchParams.get('id') || ''
      const body = await readJson(request)
      const creds = await credentialsFor(env.DB, session.user.id)
      if ((creds.results || []).length <= 1) return error(409, 'last passkey cannot be removed', { ...cors, 'X-Error-Code': 'last-way-in' })
      const proof = await verifyOwnerProof(request, env, session.user.id, body)
      if (!proof.ok) return error(proof.status, proof.message, cors)
      const result = await env.DB.prepare('DELETE FROM passkeys WHERE credential_id=? AND user_id=?').bind(id, session.user.id).run()
      if (!result.meta?.changes) return error(404, 'passkey not found', cors)
      return json(200, { ok: true, ...await passkeyState(env.DB, session.user.id) }, cors)
    }

    if (method === 'POST' && path === '/api/account/device-link') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      const proof = await verifyOwnerProof(request, env, session.user.id, body)
      if (!proof.ok) return error(proof.status, proof.message, cors)
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
      const raw = crypto.getRandomValues(new Uint8Array(8))
      const code = [...raw].map(x => alphabet[x % alphabet.length]).join('')
      const expires = Date.now() + DEVICE_LINK_MS
      await env.DB.prepare('INSERT INTO device_link_codes(code_hash,user_id,expires_at) VALUES(?,?,?)').bind(await shaText(code), session.user.id, expires).run()
      return json(200, { code, expires }, cors)
    }
    if (method === 'POST' && path === '/api/device-link/options') {
      const body = await readJson(request)
      const code = String(body.code || '').trim().toUpperCase()
      const codeHash = await shaText(code)
      const link = await env.DB.prepare('SELECT user_id,expires_at FROM device_link_codes WHERE code_hash=? AND expires_at>?').bind(codeHash, Date.now()).first()
      if (!link) return error(400, 'that code is wrong, used or expired', { ...cors, 'X-Error-Code': 'link-invalid' })
      const user = await env.DB.prepare('SELECT id,name,session_version,disabled FROM users WHERE id=?').bind(link.user_id).first()
      if (!user || user.disabled) return error(400, 'that code is wrong, used or expired', cors)
      const credentials = await credentialsFor(env.DB, user.id)
      const options = await createOptions(env, { userId: user.id, name: user.name, credentials: credentials.results || [] })
      const cid = await storeChallenge(env.DB, { kind: 'link', challenge: options.challenge, uid: user.id, codeHash, sv: user.session_version })
      return json(200, { cid, options, name: user.name }, cors)
    }
    if (method === 'POST' && path === '/api/device-link/verify') {
      const body = await readJson(request)
      const challenge = await consumeChallenge(env.DB, body.cid)
      if (!challenge || challenge.kind !== 'link') return error(400, 'challenge expired — try again', cors)
      const verification = await verifyRegistration(env, challenge.challenge, body.credential)
      if (!verification.verified) return error(400, 'passkey could not be verified', cors)
      const cred = credentialFromVerification(verification, body.credential, challenge.uid, body.name)
      if (!cred) return error(400, 'invalid passkey response', cors)
      const link = await env.DB.prepare('DELETE FROM device_link_codes WHERE code_hash=? AND user_id=? AND expires_at>? RETURNING user_id').bind(challenge.codeHash, challenge.uid, Date.now()).first()
      if (!link) return error(400, 'that code is wrong, used or expired', cors)
      try {
        const created = utcNow()
        await env.DB.prepare('INSERT INTO passkeys(credential_id,user_id,public_key,counter,transports,display_name,created_at,last_used) VALUES(?,?,?,?,?,?,?,?)').bind(...newCredentialParams(cred, created)).run()
      } catch { return error(409, 'this passkey already belongs to a profile', cors) }
      const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(challenge.uid).first()
      if (!user || Number(user.session_version) !== Number(challenge.sv)) return error(401, 'not signed in', cors)
      const token = await makeToken(user, env)
      return json(200, { user: publicUser(user) }, { ...cors, 'Set-Cookie': sessionCookie(token, env) })
    }

    if (method === 'POST' && path === '/api/pair/create') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
      const raw = crypto.getRandomValues(new Uint8Array(8))
      const code = [...raw].map(x => alphabet[x % alphabet.length]).join('')
      await env.DB.prepare('INSERT INTO pair_codes(code_hash,user_id,expires_at) VALUES(?,?,?)').bind(await shaText(code), session.user.id, Date.now() + PAIR_MS).run()
      return json(200, { code }, cors)
    }
    if (method === 'POST' && path === '/api/pair/redeem') {
      const body = await readJson(request)
      const hash = await shaText(String(body.code || '').trim().toUpperCase())
      const row = await env.DB.prepare('DELETE FROM pair_codes WHERE code_hash=? AND expires_at>? RETURNING user_id').bind(hash, Date.now()).first()
      if (!row) return error(400, 'invalid or expired code', cors)
      const user = await env.DB.prepare('SELECT * FROM users WHERE id=? AND disabled=0').bind(row.user_id).first()
      if (!user) return error(400, 'invalid or expired code', cors)
      return json(200, { token: await makeToken(user, env), user: publicUser(user) }, cors)
    }

    if (method === 'GET' && path === '/api/data') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const row = await env.DB.prepare('SELECT document,rev FROM states WHERE user_id=?').bind(session.user.id).first()
      await env.DB.prepare('UPDATE users SET last_pull=? WHERE id=?').bind(Date.now(), session.user.id).run()
      let state = null
      try { if (row) state = JSON.parse(row.document) } catch { state = null }
      return json(200, { state, rev: Number(row?.rev || 0) }, cors)
    }
    if (method === 'GET' && path === '/api/data/rev') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const row = await env.DB.prepare('SELECT rev FROM states WHERE user_id=?').bind(session.user.id).first()
      return json(200, { rev: Number(row?.rev || 0) }, cors)
    }
    if (method === 'PUT' && path === '/api/data') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      if (!validProfileState(body.state)) return error(400, 'state required or invalid state', cors)
      const state = JSON.parse(JSON.stringify(body.state))
      for (const key of ['workouts', 'routines']) if (Array.isArray(state[key])) state[key] = records(state[key])
      delete state.active
      const current = await env.DB.prepare('SELECT document,rev FROM states WHERE user_id=?').bind(session.user.id).first()
      let currentState = null
      try { if (current) currentState = JSON.parse(current.document) } catch { currentState = null }
      const currentRev = Number(current?.rev || 0)
      if (body.baseRev != null && Number(body.baseRev) !== currentRev) return json(409, { error: 'conflict', rev: currentRev, state: currentState }, cors)
      if (Number(currentState?.resetAt || 0) > Number(state.resetAt || 0)) {
        state.resetAt = currentState.resetAt
        if (isObject(currentState.resetIds)) state.resetIds = currentState.resetIds
        else delete state.resetIds
      }
      const nextRev = currentRev + 1
      const now = Date.now()
      state._rev = nextRev
      const update = await env.DB.prepare(`INSERT INTO states(user_id,document,rev,updated_at) VALUES(?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET document=excluded.document,rev=excluded.rev,updated_at=excluded.updated_at
        WHERE states.rev=?`).bind(session.user.id, JSON.stringify(state), nextRev, now, currentRev).run()
      if (!update.meta?.changes) {
        const latest = await env.DB.prepare('SELECT document,rev FROM states WHERE user_id=?').bind(session.user.id).first()
        let latestState = null
        try { if (latest) latestState = JSON.parse(latest.document) } catch { latestState = null }
        return json(409, { error: 'conflict', rev: Number(latest?.rev || 0), state: latestState }, cors)
      }
      try { await reconcileMedia(env, session.user.id, state) } catch (e) { console.error('media reference reconciliation failed', e) }
      return json(200, { ok: true, rev: nextRev }, cors)
    }

    const mediaMatch = path.match(/^\/api\/media\/([a-f0-9]{64})$/i)
    if (mediaMatch && method === 'PUT') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      if (!env.MEDIA) return error(503, 'media storage is unavailable', cors)
      const hash = mediaMatch[1].toLowerCase()
      const announced = Number(request.headers.get('content-length') || 0)
      const requested = declaredCategory(request.headers.get('content-type'))
      if (!requested) return mediaError(415, 'media-type', {}, cors)
      const cap = MEDIA_CAPS[requested]
      if (announced > cap) return mediaError(413, 'media-too-large', { maxMB: cap / 1024 / 1024 }, cors)
      const existing = await env.DB.prepare('SELECT mime,size FROM media WHERE user_id=? AND hash=?').bind(session.user.id, hash).first()
      if (existing) return json(200, { ok: true, hash, mime: existing.mime, size: Number(existing.size), existed: true }, cors)
      let bytes
      try { bytes = await readBoundedBytes(request, cap) }
      catch (e) { if (e.status === 413) return mediaError(413, 'media-too-large', { maxMB: cap / 1024 / 1024 }, cors); throw e }
      const digest = await sha256(bytes)
      if (digest !== hash) return mediaError(400, 'hash-mismatch', {}, cors)
      const detected = sniff(new Uint8Array(bytes))
      if (!detected || (requested === 'gif' ? detected.category !== 'gif' : requested === 'image' ? detected.category !== 'image' : detected.category !== 'video')) return mediaError(415, 'media-type', {}, cors)
      if (detected.category === 'video' && ['mp4', 'mov'].includes(detected.ext)) {
        const seconds = mp4Duration(new Uint8Array(bytes))
        if (seconds == null) return mediaError(415, 'media-invalid', {}, cors)
        if (seconds > VIDEO_SECONDS + 1) return mediaError(413, 'media-too-long', { maxSec: VIDEO_SECONDS }, cors)
      }
      let usage = await getMediaUsage(env.DB, session.user.id)
      if (usage.bytes + bytes.byteLength > MEDIA_QUOTA) {
        try {
          const stateRow = await env.DB.prepare('SELECT document FROM states WHERE user_id=?').bind(session.user.id).first()
          let state = null
          try { if (stateRow) state = JSON.parse(stateRow.document) } catch { state = null }
          await reconcileMedia(env, session.user.id, state)
          await collectUnreferenced(env, session.user.id, 60 * 60_000)
          usage = await getMediaUsage(env.DB, session.user.id)
        } catch (e) { console.error('media quota cleanup failed', e) }
      }
      if (usage.bytes + bytes.byteLength > MEDIA_QUOTA) return mediaError(413, 'media-quota', { usedMB: Math.round(usage.bytes / 104857.6) / 10, quotaMB: MEDIA_QUOTA / 1024 / 1024 }, cors)
      const key = `${session.user.id}/${hash}.${detected.ext}`
      try {
        await env.MEDIA.put(key, bytes, { httpMetadata: { contentType: detected.mime }, customMetadata: { userId: session.user.id, sha256: hash } })
        const uploadedAt = Date.now()
        await env.DB.prepare('INSERT INTO media(user_id,hash,object_key,mime,size,ext,created_at,unreferenced_at) VALUES(?,?,?,?,?,?,?,?)').bind(session.user.id, hash, key, detected.mime, bytes.byteLength, detected.ext, uploadedAt, uploadedAt).run()
      } catch {
        try { await env.MEDIA.delete(key) } catch { /* leave failed cleanup for operator visibility */ }
        return mediaError(503, 'storage-full', {}, cors)
      }
      return json(201, { ok: true, hash, mime: detected.mime, size: bytes.byteLength, existed: false }, cors)
    }
    if (mediaMatch && method === 'GET') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      if (!env.MEDIA) return error(503, 'media storage is unavailable', cors)
      const row = await env.DB.prepare('SELECT object_key,mime,size FROM media WHERE user_id=? AND hash=?').bind(session.user.id, mediaMatch[1].toLowerCase()).first()
      if (!row) return mediaError(404, 'media-missing', {}, cors)
      const object = await env.MEDIA.get(row.object_key)
      if (!object) {
        await env.DB.prepare('DELETE FROM media WHERE user_id=? AND hash=?').bind(session.user.id, mediaMatch[1].toLowerCase()).run()
        return mediaError(404, 'media-missing', {}, cors)
      }
      const headers = new Headers({ ...cors, 'Content-Type': row.mime, 'Content-Length': String(row.size), 'Cache-Control': 'private, max-age=86400', ETag: object.httpEtag })
      return new Response(object.body, { status: 200, headers })
    }
    if (method === 'POST' && path === '/api/media/missing') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      const body = await readJson(request)
      const hashes = [...new Set((Array.isArray(body.hashes) ? body.hashes : []).filter(h => typeof h === 'string' && /^[a-f0-9]{64}$/i.test(h)).map(h => h.toLowerCase()))].slice(0, 2000)
      const found = new Set()
      for (let i = 0; i < hashes.length; i += 80) {
        const batch = hashes.slice(i, i + 80)
        if (!batch.length) continue
        const placeholders = batch.map(() => '?').join(',')
        const rows = await env.DB.prepare(`SELECT hash FROM media WHERE user_id=? AND hash IN (${placeholders})`).bind(session.user.id, ...batch).all()
        for (const row of rows.results || []) found.add(row.hash)
      }
      return json(200, { missing: hashes.filter(h => !found.has(h)), usage: await getMediaUsage(env.DB, session.user.id) }, cors)
    }
    if (method === 'POST' && path === '/api/media/sweep') {
      const session = await getSession(request, env)
      if (!session) return error(401, 'not signed in', cors)
      if (!env.MEDIA) return error(503, 'media storage is unavailable', cors)
      const row = await env.DB.prepare('SELECT document FROM states WHERE user_id=?').bind(session.user.id).first()
      let state = null
      try { if (row) state = JSON.parse(row.document) } catch { state = null }
      await reconcileMedia(env, session.user.id, state)
      return json(200, await collectUnreferenced(env, session.user.id, 14 * 24 * 60 * 60_000), cors)
    }
    if (path.startsWith('/api/')) return error(404, 'not found', cors)
    return error(404, 'not found', cors)
  } catch (e) {
    const status = Number(e?.status) || 500
    return error(status, status === 500 ? 'internal server error' : e.message, cors)
  }
}

export default { fetch: handleRequest }
