import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Play, ShieldAlert, TrendingUp, ShieldCheck, Target, Globe, CheckCircle2,
} from 'lucide-react'
import { Button, Card, Input, StatCard, SectionLabel, Spinner, cn } from '../components/ui.jsx'
import { API } from '../lib/api.js'
import { host } from '../lib/format.js'

const MODULES = [
  'Cross-Domain', 'Sitemap', 'Robots', 'Git Enumeration',
  'Headers', 'Web Server', 'Clickjacking', 'Error & Exceptions',
  'Host Header Injection', 'Unencrypted Communication', 'HTTP Bypass', 'TRACE Method',
  'Autocomplete', 'Request Splitting', 'Response Splitting', 'Directory Listing',
  'JS Enumeration', 'Username Enumeration', 'CAPTCHA', 'Insecure CORS',
]

// Input-driven tools from the Security Tools section — shown alongside the
// automated modules so the dashboard reflects all available test cases.
const MANUAL_MODULES = ['JWT Analysis']

// Every test case shown in the dashboard grid (automated + manual).
const ALL_MODULES = [...MODULES, ...MANUAL_MODULES]

export default function Dashboard({ onScanStarted }) {
  const [url, setUrl] = useState('')
  const [account, setAccount] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [stats, setStats] = useState(null)
  const navigate = useNavigate()

  useEffect(() => {
    fetch(`${API}/api/scan/history`)
      .then(r => r.json())
      .then(d => {
        const scans = d.scans || []
        const done = scans.filter(s => s.status === 'completed')
        setStats({
          totalScans: scans.length,
          critical: done.reduce((a, s) => a + (s.critical_count || 0), 0),
          high: done.reduce((a, s) => a + (s.high_count || 0), 0),
          totalFindings: done.reduce((a, s) => a + (s.total_findings || 0), 0),
          cleanScans: done.filter(s => s.total_findings === 0).length,
          lastTarget: done[0]?.target_url || null,
        })
      })
      .catch(() => {})
  }, [])

  async function startScan() {
    const trimmed = url.trim()
    if (!trimmed) { setError('Enter a target URL'); return }
    const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
    setError(''); setLoading(true)
    try {
      const acct = account.trim()
      const res = await fetch(`${API}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: withScheme, ...(acct ? { known_account_email: acct } : {}) }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to start scan')
      onScanStarted?.(data.scan_id)
      navigate(`/scan/${data.scan_id}`)
    } catch (e) {
      setError(e.message)
      setLoading(false)
    }
  }

  return (
    <div className="animate-fade-in space-y-10">
      {/* ── Hero: the target URL is the centerpiece ── */}
      <section className="relative overflow-hidden rounded-2xl border border-border bg-card px-6 py-14 text-center shadow-card sm:py-16">
        {/* soft backdrop */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-40 opacity-70"
          style={{ background: 'radial-gradient(60% 100% at 50% 0%, var(--primary-soft), transparent 70%)' }}
        />
        <div className="relative">
          <div className="mb-4 inline-flex items-center gap-1.5 rounded-full border border-border bg-background px-3 py-1 text-xs font-medium text-muted-foreground">
            <span className="h-1.5 w-1.5 rounded-full bg-primary" />
            Web Application Security Assessment
          </div>
          <h1 className="mx-auto max-w-2xl text-3xl font-semibold tracking-tight text-foreground sm:text-4xl">
            Know Your Attack Surface
          </h1>
          <p className="mx-auto mt-3 max-w-xl text-sm text-muted-foreground sm:text-base">
            Enter a target URL to run 20 automated test modules with intelligent crawling and AI-assisted analysis. All testing is strictly scoped to the target host.
          </p>

          {/* Big URL input */}
          <div className="mx-auto mt-8 flex max-w-2xl flex-col gap-3 sm:flex-row">
            <div className={cn(
              'relative flex-1 rounded-xl border bg-background transition-colors',
              error ? 'border-red-400 ring-2 ring-red-500/20' : 'border-border-strong focus-within:border-primary focus-within:ring-2 focus-within:ring-ring/40',
            )}>
              <Globe size={20} className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-subtle-foreground" />
              <input
                id="target"
                className="h-14 w-full bg-transparent pl-12 pr-4 font-mono text-base text-foreground placeholder:font-sans placeholder:text-subtle-foreground focus:outline-none"
                placeholder="Enter Your Target URL"
                value={url}
                autoFocus
                aria-label="Target URL"
                aria-invalid={!!error}
                onChange={e => { setUrl(e.target.value); setError('') }}
                onKeyDown={e => e.key === 'Enter' && startScan()}
              />
            </div>
            <Button size="xl" className="shrink-0 sm:w-44" onClick={startScan} disabled={loading}>
              {loading ? <><Spinner size={17} /> Starting…</> : <><Play size={16} fill="currentColor" /> Start scan</>}
            </Button>
          </div>

          {error && <p className="mt-3 text-sm font-medium text-red-600 dark:text-red-400" role="alert">{error}</p>}

          {/* Optional known account (improves login-form enumeration coverage) */}
          <div className="mx-auto mt-4 max-w-2xl text-left">
            <label htmlFor="account" className="mb-1.5 block text-xs font-medium text-foreground">
              Known test account <span className="font-normal text-muted-foreground">(optional) — a real account that exists on the target. Enables stronger username-enumeration detection. Leave blank for black-box scans.</span>
            </label>
            <Input
              id="account"
              icon={Target}
              placeholder="realuser@target.com (leave blank if none)"
              value={account}
              onChange={e => setAccount(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && startScan()}
            />
          </div>
        </div>
      </section>

      {/* Session overview */}
      {stats && stats.totalScans > 0 && (
        <div>
          <SectionLabel className="mb-3">Session overview</SectionLabel>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            <StatCard icon={Target} label="Total scans" value={stats.totalScans} tone="primary" />
            <StatCard icon={ShieldAlert} label="Critical" value={stats.critical} tone="critical" />
            <StatCard icon={TrendingUp} label="High" value={stats.high} tone="high" />
            <StatCard icon={ShieldCheck} label="Clean scans" value={stats.cleanScans} tone="low" />
            <StatCard icon={Target} label="Last target" value={stats.lastTarget ? host(stats.lastTarget) : '—'} small />
          </div>
        </div>
      )}

      {/* Modules */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <SectionLabel>Test modules</SectionLabel>
          <span className="text-xs text-muted-foreground">{ALL_MODULES.length} Modules</span>
        </div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
          {ALL_MODULES.map(m => (
            <div key={m} className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              <CheckCircle2 size={13} className="shrink-0 text-emerald-500" />
              <span className="truncate">{m}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
