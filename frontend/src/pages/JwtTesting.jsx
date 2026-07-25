import { useState } from 'react'
import { KeyRound, Play, ShieldAlert, ShieldCheck, Clock } from 'lucide-react'
import { Button, Card, CardHeader, Input, Spinner, SectionLabel, EmptyState } from '../components/ui.jsx'
import AddToReport from '../components/AddToReport.jsx'
import { API } from '../lib/api.js'

/* ── shared helpers ─────────────────────────────────────── */
function Field({ label, children, hint }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
      {hint && <span className="block text-2xs text-subtle-foreground">{hint}</span>}
    </label>
  )
}

async function postJSON(path, body) {
  const r = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(data.detail || `Request failed (${r.status})`)
  return data
}

const Pane = ({ label, children }) => (
  <div className="flex min-w-0 flex-col">
    <div className="border-b border-border bg-muted/40 px-3 py-1.5 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
      {label}
    </div>
    <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all p-3 text-2xs leading-relaxed text-foreground">
      {children || '—'}
    </pre>
  </div>
)

/* Decode a JWT client-side into { header, payload, signature }. */
function decodeJwt(tok) {
  const parts = String(tok || '').split('.')
  const dec = (s) => {
    if (!s) return null
    try {
      let b = s.replace(/-/g, '+').replace(/_/g, '/')
      b += '='.repeat((4 - (b.length % 4)) % 4)
      return JSON.parse(decodeURIComponent(escape(atob(b))))
    } catch { return null }
  }
  return { header: dec(parts[0]), payload: dec(parts[1]), signature: parts[2] ?? '' }
}

/* Pretty-print JSON with jwt.io-style token coloring. Input is escaped first,
 * so the colored markup is safe to inject. */
const escHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
function hlJson(data) {
  if (data == null) return '<span class="text-subtle-foreground">— could not decode —</span>'
  return escHtml(JSON.stringify(data, null, 2))
    .replace(/"([^"\n]+)":/g, '<span class="text-sky-600 dark:text-sky-400">"$1"</span>:')
    .replace(/: "([^"\n]*)"/g, ': <span class="text-emerald-600 dark:text-emerald-400">"$1"</span>')
    .replace(/: (-?\d+(?:\.\d+)?)/g, ': <span class="text-amber-600 dark:text-amber-400">$1</span>')
    .replace(/: (true|false|null)/g, ': <span class="text-amber-600 dark:text-amber-400">$1</span>')
}
function JsonBlock({ label, data }) {
  return (
    <div>
      <div className="mb-1 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">{label}</div>
      <pre
        className="overflow-auto rounded-md border border-border bg-elevated p-2.5 text-2xs leading-relaxed text-foreground"
        dangerouslySetInnerHTML={{ __html: hlJson(data) }}
      />
    </div>
  )
}

/* Colored severity badge (matches the report's per-test-case severity). */
const SEV_BADGE = {
  critical: 'bg-red-500/10 text-red-600 dark:text-red-400 ring-red-500/30',
  high:     'bg-orange-500/10 text-orange-600 dark:text-orange-400 ring-orange-500/30',
  medium:   'bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-amber-500/30',
  low:      'bg-sky-500/10 text-sky-600 dark:text-sky-400 ring-sky-500/30',
  info:     'bg-slate-500/10 text-slate-600 dark:text-slate-400 ring-slate-500/30',
}
function SeverityBadge({ severity }) {
  const s = String(severity || 'info').toLowerCase()
  return (
    <span className={`shrink-0 rounded px-1.5 py-0.5 text-2xs font-semibold uppercase ring-1 ring-inset ${SEV_BADGE[s] || SEV_BADGE.info}`}>
      {s}
    </span>
  )
}

/* Burp-style row: forged request/token on the left, server response on the right. */
function BurpRow({ c }) {
  const vuln = c.vulnerable
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <div className="flex items-center justify-between gap-2 border-b border-border bg-card px-3 py-2">
        <span className="flex items-center gap-2 text-sm font-medium text-foreground">
          {c.status_code === null ? <Clock size={14} className="text-subtle-foreground" />
            : vuln ? <ShieldAlert size={14} className="text-red-500" />
            : <ShieldCheck size={14} className="text-emerald-500" />}
          {c.name}
          {c.vulnerable && <SeverityBadge severity={c.severity} />}
          <span className="text-xs font-normal text-subtle-foreground">({c.technique})</span>
        </span>
        {c.status_code !== null && (
          <span className={`rounded px-2 py-0.5 text-2xs font-semibold ${vuln ? 'bg-red-500/10 text-red-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
            {vuln ? 'VULNERABLE' : 'SAFE'} · HTTP {c.status_code}
          </span>
        )}
      </div>
      <div className="grid divide-y divide-border md:grid-cols-2 md:divide-x md:divide-y-0">
        <div className="flex min-w-0 flex-col">
          <div className="border-b border-border bg-muted/40 px-3 py-1.5 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
            Request
          </div>
          <div className="space-y-2.5 p-3">
            {(() => {
              const d = decodeJwt(c.token)
              return (
                <>
                  <JsonBlock label="Decoded Header" data={d.header} />
                  <JsonBlock label="Decoded Payload" data={d.payload} />
                  <div>
                    <div className="mb-1 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">Signature</div>
                    <pre className="overflow-auto break-all rounded-md border border-border bg-elevated p-2.5 text-2xs text-foreground">
                      {d.signature || '(empty)'}
                    </pre>
                  </div>
                </>
              )
            })()}
          </div>
        </div>
        <Pane label="Server response">{c.response_data}</Pane>
      </div>
    </div>
  )
}

/* ── page ───────────────────────────────────────────────── */
export default function JwtTesting() {
  const [token, setToken] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [res, setRes] = useState(null)

  const run = async () => {
    setErr(''); setRes(null); setLoading(true)
    try {
      setRes(await postJSON('/api/tools/jwt', { token, target_url: endpoint || null }))
    } catch (e) { setErr(e.message) } finally { setLoading(false) }
  }

  return (
    <div className="animate-fade-in space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">JWT Analysis</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Analyze JWT security by validating signatures, algorithms, and token lifetime.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        {/* ── Input column ── */}
        <div className="lg:col-span-4">
          <Card className="lg:sticky lg:top-6">
            <CardHeader
              title={<span className="flex items-center gap-2"><KeyRound size={15} /> Token &amp; Endpoint</span>}
            />
            <div className="space-y-4 p-5 pt-3">
              <Field label="JWT Token">
                <textarea
                  value={token}
                  onChange={e => setToken(e.target.value)}
                  placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SIG"
                  rows={5}
                  className="w-full rounded-lg border border-border bg-elevated px-3 py-2 font-mono text-xs text-foreground placeholder:text-subtle-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring/50"
                />
              </Field>
              <Field label="Endpoint URL">
                <Input value={endpoint} onChange={e => setEndpoint(e.target.value)} placeholder="https://example.com/api/profile" />
              </Field>
              <Button className="w-full" onClick={run} disabled={loading || !token.trim() || !endpoint.trim()}>
                {loading ? <Spinner size={14} /> : <Play size={14} />} Run All Testcases
              </Button>
              {err && <p className="text-xs text-red-600 dark:text-red-400">{err}</p>}
            </div>
          </Card>
        </div>

        {/* ── Results column ── */}
        <div className="lg:col-span-8">
          {!res ? (
            <EmptyState
              icon={KeyRound}
              title="No results yet"
              description="Paste a token and endpoint, then run the test cases. Decoded claims and the four attack replays will appear here."
            />
          ) : (
            <div className="space-y-5">
              {/* Decoded claims */}
              <div className="grid gap-3 sm:grid-cols-2">
                <Card className="overflow-hidden">
                  <div className="border-b border-border px-4 py-2"><SectionLabel>Header</SectionLabel></div>
                  <pre className="max-h-48 overflow-auto p-3 text-2xs leading-relaxed text-foreground">{JSON.stringify(res.header, null, 2)}</pre>
                </Card>
                <Card className="overflow-hidden">
                  <div className="border-b border-border px-4 py-2"><SectionLabel>Payload</SectionLabel></div>
                  <pre className="max-h-48 overflow-auto p-3 text-2xs leading-relaxed text-foreground">{JSON.stringify(res.payload, null, 2)}</pre>
                </Card>
              </div>

              {/* Expiry test */}
              <div className={`rounded-lg border px-3 py-2.5 ${res.expiry.vulnerable ? 'border-red-500/40 bg-red-500/5' : 'border-emerald-500/40 bg-emerald-500/5'}`}>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {res.expiry.vulnerable
                    ? <ShieldAlert size={14} className="text-red-500" />
                    : <ShieldCheck size={14} className="text-emerald-500" />}
                  <span className={`font-semibold ${res.expiry.vulnerable ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                    Token Expiration: {res.expiry.vulnerable ? 'VULNERABLE' : 'SAFE'}
                  </span>
                  {res.expiry.vulnerable && <SeverityBadge severity={res.expiry.severity || 'info'} />}
                  <span className="text-muted-foreground">— {res.expiry.label}</span>
                </div>
                <div className="mt-1.5 grid gap-0.5 pl-6 font-mono text-2xs text-muted-foreground">
                  <span>iat (UTC): {res.expiry.iat_human}</span>
                  <span>exp (UTC): {res.expiry.exp_human}</span>
                </div>
              </div>

              {/* Burp-style attack replays */}
              <div className="space-y-3">
                <SectionLabel>Algorithm &amp; Signature Tests</SectionLabel>
                {res.checks.map((c, i) => <BurpRow key={i} c={c} />)}
              </div>

              {/* Attach to a scan report */}
              <AddToReport tool="jwt" result={res} />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
