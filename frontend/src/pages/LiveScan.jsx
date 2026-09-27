import { useState, useEffect, useRef, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Terminal, CheckCircle2, ChevronDown, ChevronRight, ExternalLink, Download,
  AlertOctagon, X, Search, Cpu, Globe, Pause, Play, Square, ArrowUpDown,
  Loader2, Plus, ShieldCheck, MinusCircle, Sparkles, Link2,
} from 'lucide-react'
import { Button, Card, Input, IconButton, SeverityBadge, SEV_ICON, ProgressBar, cn } from '../components/ui.jsx'
import { API, WS, SEV_ORDER, SEVERITIES, PLAYWRIGHT_MODULES } from '../lib/api.js'
import { moduleLabel } from '../lib/format.js'
import { TESTCASE_TITLES, TESTCASE_INFO, TESTCASE_ORDER, isBenignFinding } from '../lib/testcases.js'

export default function LiveScan({ scanId: scanIdProp, onScanEnded }) {
  const { id: paramId } = useParams()
  const id = scanIdProp || paramId
  const navigate = useNavigate()

  const [scan, setScan] = useState(null)
  const [logs, setLogs] = useState([])
  const [findings, setFindings] = useState([])
  const [modules, setModules] = useState({})
  const [status, setStatus] = useState('connecting')
  const [summary, setSummary] = useState(null)
  const [ai, setAi] = useState(null)   // { summary, correlations }
  const [critAlert, setCritAlert] = useState(null)
  const [isPaused, setIsPaused] = useState(false)
  const [expanded, setExpanded] = useState({})
  const [activeTab, setActiveTab] = useState({})
  const [showVerify, setShowVerify] = useState(false)
  const [verifyExpanded, setVerifyExpanded] = useState({})
  const [verifyTab, setVerifyTab] = useState({})
  const [overallPct, setOverallPct] = useState(0)

  const [crawlStatus, setCrawlStatus] = useState('idle')
  const [crawlResult, setCrawlResult] = useState(null)
  const [crawlProgress, setCrawlProgress] = useState(null)
  const [crawlExpanded, setCrawlExpanded] = useState(false)
  const [urlFilter, setUrlFilter] = useState('all')

  const [search, setSearch] = useState('')
  const [filterSev, setFilterSev] = useState('all')
  const [sortField, setSortField] = useState('severity')
  const [sortDir, setSortDir] = useState('asc')
  const [pendingAction, setPendingAction] = useState(null)   // 'pausing' | 'resuming' | 'stopping' | null

  const logsRef = useRef(null)
  const wsRef = useRef(null)

  // Load existing scan
  useEffect(() => {
    fetch(`${API}/api/scan/${id}`)
      .then(r => r.json())
      .then(d => {
        if (d.scan) setScan(d.scan)
        if (d.findings) setFindings(d.findings.map(normUrls))
        if (d.scan?.ai_summary || d.scan?.ai_correlations?.length) {
          setAi({ summary: d.scan.ai_summary || '', correlations: d.scan.ai_correlations || [] })
        }
        if (d.scan?.status === 'completed') {
          setStatus('completed'); setOverallPct(100)
          setSummary({
            counts: {
              total: d.scan.total_findings, critical: d.scan.critical_count,
              high: d.scan.high_count, medium: d.scan.medium_count,
              low: d.scan.low_count, info: d.scan.info_count,
            },
          })
        }
      })
      .catch(() => {})
  }, [id])

  // WebSocket
  useEffect(() => {
    const ws = new WebSocket(`${WS}/ws/${id}`)
    wsRef.current = ws
    ws.onopen = () => setStatus('running')
    ws.onmessage = evt => { try { handleEvent(JSON.parse(evt.data)) } catch {} }
    ws.onclose = () => setStatus(s => (['completed', 'failed', 'stopped'].includes(s) ? s : 'disconnected'))
    return () => ws.close()
  }, [id])

  const handleEvent = useCallback((event) => {
    const { event: type, data } = event
    switch (type) {
      case 'scan_started':
        setStatus('running')
        addLog(`Scan started on ${data.target_url}`, 'info')
        addLog(`${data.total_modules} modules queued`, 'muted')
        break
      case 'crawl_started':
        setCrawlStatus('running'); setCrawlProgress(null); addLog(`Playwright crawl started → ${data.target_url}`, 'module'); break
      case 'crawl_progress':
        // Flip to 'running' here too: if the WS connected a beat after the scan
        // started, crawl_started was missed — the first progress event recovers.
        setCrawlStatus(s => (s === 'done' || s === 'failed') ? s : 'running')
        setCrawlProgress({ visited: data.pages_visited, total: data.pages_total, urls: data.urls_found })
        break
      case 'crawl_completed':
        setCrawlStatus('done'); setCrawlResult(data); setCrawlExpanded(true)
        addLog(`Crawl complete — ${data.url_count} URLs in ${data.crawl_duration}s`, 'success')
        addLog(`API: ${data.api_count}  Forms: ${data.form_count}  JS: ${data.js_count}`, 'muted')
        break
      case 'crawl_failed':
        setCrawlStatus('failed'); addLog(`Playwright crawl failed: ${data.reason}`, 'error'); break
      case 'module_started':
        setModules(m => ({ ...m, [data.module]: {
          status: 'running', index: data.index, total: data.total,
          percent: 0, elapsed: null, findingCount: 0,
          playwright: data.playwright_enabled ?? PLAYWRIGHT_MODULES.has(data.module),
        }}))
        setOverallPct(data.percent_complete ?? 0)
        addLog(`${moduleLabel(data.module)} — starting (${data.index}/${data.total})`, 'module')
        break
      case 'module_progress':
        setModules(m => ({ ...m, [data.module]: {
          ...(m[data.module] || {}), percent: data.percent ?? 0,
        }}))
        break
      case 'module_completed':
        setModules(m => ({ ...m, [data.module]: {
          ...(m[data.module] || {}), status: data.error ? 'error' : 'done',
          elapsed: data.elapsed_seconds, findingCount: data.finding_count,
          percent: data.percent_complete ?? 100,
        }}))
        setOverallPct(data.percent_complete ?? 0)
        addLog(`${moduleLabel(data.module)} — ${data.finding_count} finding(s) in ${data.elapsed_seconds}s`,
          data.finding_count > 0 ? 'success' : 'muted')
        if (data.error) addLog(`  Error: ${data.error}`, 'error')
        break
      case 'finding_discovered':
        setFindings(f => [...f, normUrls(data)])
        addLog(`${data.severity.toUpperCase()}: ${data.title}`, 'finding'); break
      case 'critical_finding':
        setFindings(f => [...f, normUrls(data)]); setCritAlert(data)
        addLog(`CRITICAL: ${data.title}`, 'critical'); break
      case 'log':
        addLog(data.message, data.level); break
      case 'scan_completed':
        setStatus('completed'); setOverallPct(100); setSummary(data); setPendingAction(null); onScanEnded?.()
        if (data.ai_summary || data.ai_correlations?.length) {
          setAi({ summary: data.ai_summary || '', correlations: data.ai_correlations || [] })
        }
        addLog('Scan complete.', 'success')
        addLog(`Total findings: ${data.counts?.total || 0}`, 'info'); break
      case 'scan_failed':
        setStatus('failed'); setPendingAction(null); onScanEnded?.(); addLog(`Scan failed: ${data.reason}`, 'error'); break
      case 'scan_stopped':
        setStatus('stopped'); setIsPaused(false); setPendingAction(null); onScanEnded?.()
        addLog('Scan stopped by user.', 'error')
        if (data.counts) setSummary({ counts: data.counts }); break
      case 'scan_paused':
        setIsPaused(true); setPendingAction(null); addLog('Scan paused.', 'warning'); break
      case 'scan_resumed':
        setIsPaused(false); setPendingAction(null); addLog('Scan resumed.', 'info'); break
    }
  }, [])

  function addLog(message, level = 'info') {
    setLogs(l => [...l.slice(-500), { message, level, ts: Date.now() }])
  }
  function normUrls(f) {
    return { ...f, affected_urls: typeof f.affected_urls === 'string'
      ? (() => { try { return JSON.parse(f.affected_urls) } catch { return [] } })()
      : (f.affected_urls || []) }
  }

  useEffect(() => { if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight }, [logs])

  // Real vulnerabilities vs benign "…Not Vulnerable" markers (robots/captcha/etc.)
  const vulnFindings   = findings.filter(f => !isBenignFinding(f))
  const benignFindings = findings.filter(isBenignFinding)

  const counts = vulnFindings.reduce((a, f) => (a[f.severity] = (a[f.severity] || 0) + 1, a), {})

  const filteredFindings = vulnFindings
    .filter(f => {
      if (filterSev !== 'all' && f.severity !== filterSev) return false
      if (search) {
        const q = search.toLowerCase()
        return f.title?.toLowerCase().includes(q) || f.module?.toLowerCase().includes(q) || f.description?.toLowerCase().includes(q)
      }
      return true
    })
    .sort((a, b) => {
      let diff = 0
      if (sortField === 'severity') diff = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4)
      else if (sortField === 'module') diff = (a.module || '').localeCompare(b.module || '')
      else if (sortField === 'title') diff = (a.title || '').localeCompare(b.title || '')
      return sortDir === 'asc' ? diff : -diff
    })

  function toggleSort(field) {
    if (sortField === field) setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    else { setSortField(field); setSortDir('asc') }
  }

  const moduleEntries = Object.entries(modules)
  const completedModules = moduleEntries.filter(([, m]) => m.status === 'done' || m.status === 'error').length

  // ── Verification list: test cases confirmed Not Vulnerable / Not Applicable ──
  const vulnModules = new Set(vulnFindings.map(f => f.module))
  const benignByModule = benignFindings.reduce((a, f) => ((a[f.module] ||= []).push(f), a), {})
  const verification = (() => {
    const rows = []
    if (moduleEntries.length) {
      // Live scan — per-module status is known from module events.
      for (const [name, m] of moduleEntries) {
        if (vulnModules.has(name) || m.status === 'running') continue
        rows.push({
          module: name, title: TESTCASE_TITLES[name] || moduleLabel(name),
          status: m.status === 'error' ? 'not_applicable' : 'not_vulnerable',
          finding: benignByModule[name]?.[0] || null,
        })
      }
    } else {
      // Re-opened scan — a completed scan ran every module; otherwise fall back
      // to whatever benign markers were saved.
      const names = status === 'completed' ? TESTCASE_ORDER : Object.keys(benignByModule)
      for (const name of names) {
        if (vulnModules.has(name)) continue
        rows.push({
          module: name, title: TESTCASE_TITLES[name] || moduleLabel(name),
          status: 'not_vulnerable', finding: benignByModule[name]?.[0] || null,
        })
      }
    }
    return rows.sort((a, b) => a.title.localeCompare(b.title))
  })()
  const notVulnCount = verification.filter(v => v.status === 'not_vulnerable').length
  const naCount = verification.filter(v => v.status === 'not_applicable').length

  const filteredUrls = crawlResult ? (() => {
    const apiSet = new Set(crawlResult.api_endpoints || [])
    const formSet = new Set(crawlResult.forms || [])
    const jsFiles = crawlResult.js_files || []
    if (urlFilter === 'js') return jsFiles
    if (urlFilter === 'all') return [...(crawlResult.all_urls || []), ...jsFiles]
    return (crawlResult.all_urls || []).filter(url => {
      if (urlFilter === 'api') return apiSet.has(url)
      if (urlFilter === 'form') return formSet.has(url)
      if (urlFilter === 'page') return !apiSet.has(url) && !formSet.has(url)
      return true
    })
  })() : []

  // Pages = discovered URLs that are neither API endpoints nor forms.
  const pageCount = crawlResult ? (() => {
    const apiSet = new Set(crawlResult.api_endpoints || [])
    const formSet = new Set(crawlResult.forms || [])
    return (crawlResult.all_urls || []).filter(u => !apiSet.has(u) && !formSet.has(u)).length
  })() : 0

  function getUrlTag(url) {
    if (!crawlResult) return 'page'
    if ((crawlResult.api_endpoints || []).includes(url)) return 'api'
    if ((crawlResult.forms || []).includes(url)) return 'form'
    if ((crawlResult.js_files || []).includes(url)) return 'js'
    return 'page'
  }

  const PENDING_LABEL = { pause: 'pausing', resume: 'resuming', stop: 'stopping' }

  async function control(action) {
    if (action === 'stop' && !window.confirm('Stop the scan? This cannot be undone.')) return
    // Reflect the click immediately; the WS confirmation (scan_paused /
    // scan_resumed / scan_stopped) clears it once the backend actually gets there.
    setPendingAction(PENDING_LABEL[action])
    try {
      const res = await fetch(`${API}/api/scan/${id}/${action}`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
    } catch (e) {
      addLog(`${action} request failed: ${e.message}`, 'error')
      setPendingAction(null)   // request itself failed → clear the pending state
    }
  }

  // Safety net: if the backend never confirms (dropped WS, etc.), don't let the
  // transient state stick forever.
  useEffect(() => {
    if (!pendingAction) return
    const t = setTimeout(() => setPendingAction(null), 20000)
    return () => clearTimeout(t)
  }, [pendingAction])

  const isActive = status === 'running'
  const running = isActive && !isPaused

  return (
    <div className="animate-fade-in space-y-5">
      {/* Critical alert */}
      {critAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm" onClick={() => setCritAlert(null)}>
          <div className="w-full max-w-lg overflow-hidden rounded-xl border border-red-200 bg-card shadow-pop dark:border-red-500/30" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2 border-b border-border bg-red-50 px-5 py-3 text-red-700 dark:bg-red-500/10 dark:text-red-400">
              <AlertOctagon size={18} />
              <span className="text-sm font-semibold">Critical finding detected</span>
              <IconButton className="ml-auto" title="Close" onClick={() => setCritAlert(null)}><X size={16} /></IconButton>
            </div>
            <div className="space-y-3 p-5">
              <div className="text-base font-semibold text-foreground">{critAlert.title}</div>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={critAlert.severity} />
                <span className="text-xs text-muted-foreground">{moduleLabel(critAlert.module)}</span>
                {critAlert.affected_urls?.[0] && <span className="truncate font-mono text-xs text-muted-foreground">{critAlert.affected_urls[0]}</span>}
              </div>
              <p className="text-sm leading-relaxed text-muted-foreground">{critAlert.description}</p>
              <div className="flex gap-2 pt-1">
                <Button size="sm" onClick={() => {
                  setCritAlert(null); setExpanded(e => ({ ...e, [critAlert.id]: true }))
                  setTimeout(() => document.getElementById(`finding-${critAlert.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 60)
                }}><ExternalLink size={13} /> View finding</Button>
                <Button size="sm" variant="ghost" onClick={() => setCritAlert(null)}>Dismiss</Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top bar */}
      <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4 shadow-card lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm font-medium text-foreground">{scan?.target_url || `Scan ${id.slice(0, 8)}…`}</div>
          <StatusPill status={status} isPaused={isPaused} count={vulnFindings.length} pending={pendingAction} />
        </div>

        {(isActive || status === 'completed') && (
          <div className="flex items-center gap-3 lg:w-72">
            <ProgressBar value={status === 'completed' ? 100 : overallPct} className="flex-1" />
            <span className="shrink-0 font-mono text-xs text-muted-foreground tnum">
              {status === 'completed' ? '100%' : `${overallPct}%`} · {completedModules}/{moduleEntries.length || 20}
            </span>
          </div>
        )}

        <div className="flex items-center gap-2">
          {running && (
            <Button size="sm" variant="secondary" onClick={() => control('pause')} disabled={!!pendingAction}>
              {pendingAction === 'pausing' ? <><Loader2 size={13} className="animate-spin" /> Pausing…</> : <><Pause size={13} /> Pause</>}
            </Button>
          )}
          {isActive && isPaused && (
            <Button size="sm" onClick={() => control('resume')} disabled={!!pendingAction}>
              {pendingAction === 'resuming' ? <><Loader2 size={13} className="animate-spin" /> Resuming…</> : <><Play size={13} /> Resume</>}
            </Button>
          )}
          {isActive && (
            <Button size="sm" variant="danger" onClick={() => control('stop')} disabled={!!pendingAction}>
              {pendingAction === 'stopping' ? <><Loader2 size={13} className="animate-spin" /> Stopping…</> : <><Square size={13} /> Stop</>}
            </Button>
          )}
          {status === 'completed' && <ReportMenu id={id} />}
          <Button size="sm" variant="outline" onClick={() => navigate('/')}><Plus size={13} /> New</Button>
        </div>
      </div>

      {/* Main grid */}
      <div className="grid gap-5 xl:grid-cols-[380px_1fr]">
        {/* Left: crawl + modules + log */}
        <div className="space-y-5">
          {/* Playwright crawl */}
          <Card className="overflow-hidden">
            <button
              className="flex w-full items-center gap-3 px-4 py-3 text-left"
              onClick={() => crawlStatus === 'done' && setCrawlExpanded(e => !e)}
            >
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted">
                {crawlStatus === 'idle' && <Globe size={15} className="text-subtle-foreground" />}
                {crawlStatus === 'running' && <Loader2 size={15} className="animate-spin text-primary" />}
                {crawlStatus === 'done' && <CheckCircle2 size={15} className="text-emerald-500" />}
                {crawlStatus === 'failed' && <X size={15} className="text-red-500" />}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-xs font-semibold uppercase tracking-wide text-foreground">Playwright crawl</span>
                <span className="block truncate text-xs text-muted-foreground">
                  {crawlStatus === 'idle' && 'Waiting to start…'}
                  {crawlStatus === 'running' && (crawlProgress
                    ? `Crawling… ${crawlProgress.visited}/${crawlProgress.total} pages · ${crawlProgress.urls} URLs found`
                    : 'Launching browser…')}
                  {crawlStatus === 'done' && `${(crawlResult?.url_count || 0) + (crawlResult?.js_count || 0)} URLs discovered`}
                  {crawlStatus === 'failed' && 'Crawl failed — check the log'}
                </span>
              </span>
              {crawlStatus === 'done' && (crawlExpanded ? <ChevronDown size={15} className="text-subtle-foreground" /> : <ChevronRight size={15} className="text-subtle-foreground" />)}
            </button>

            {crawlStatus === 'running' && <div className="h-0.5 w-full overflow-hidden bg-muted"><div className="h-full w-1/3 animate-indeterminate bg-primary" /></div>}

            {/* Count tiles double as filters (click to filter the URL list below). */}
            {crawlStatus === 'done' && crawlResult && (
              <div className="grid grid-cols-5 gap-px border-t border-border bg-border text-center">
                {[
                  ['Page', 'page', pageCount],
                  ['API', 'api', crawlResult.api_count],
                  ['Forms', 'form', crawlResult.form_count],
                  ['JS', 'js', crawlResult.js_count],
                  ['Total', 'all', (crawlResult.url_count || 0) + (crawlResult.js_count || 0)],
                ].map(([l, key, v]) => {
                  const active = urlFilter === key && crawlExpanded
                  return (
                    <button key={l} onClick={() => { setUrlFilter(key); setCrawlExpanded(true) }}
                      title={`Show ${l}`}
                      className={cn('py-2 transition-colors', active ? 'bg-primary-soft' : 'bg-card hover:bg-muted')}>
                      <div className={cn('font-mono text-sm font-semibold tnum', active ? 'text-primary' : 'text-foreground')}>{v}</div>
                      <div className={cn('text-2xs uppercase tracking-wide', active ? 'text-primary' : 'text-subtle-foreground')}>{l}</div>
                    </button>
                  )
                })}
              </div>
            )}

            {crawlStatus === 'done' && crawlExpanded && crawlResult && (
              <div className="border-t border-border">
                <div className="max-h-80 overflow-y-auto">
                  {filteredUrls.length === 0
                    ? <div className="p-4 text-center text-xs text-muted-foreground">No URLs in this category.</div>
                    : filteredUrls.map((url, i) => (
                        <div key={i} className="flex items-start gap-2 border-b border-border px-3 py-1.5 last:border-0">
                          <span className="mt-0.5"><UrlTag tag={getUrlTag(url)} /></span>
                          <a href={url} target="_blank" rel="noreferrer" title={url}
                             className="min-w-0 flex-1 break-all font-mono text-xs leading-relaxed text-muted-foreground hover:text-primary hover:underline">
                            {url}
                          </a>
                        </div>
                      ))}
                </div>
              </div>
            )}
          </Card>

          {/* Modules */}
          <Card className="overflow-hidden">
            <div className="flex items-center gap-1.5 border-b border-border px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
              <Cpu size={12} /> Modules
            </div>
            <div className="max-h-72 divide-y divide-border overflow-y-auto">
              {moduleEntries.length === 0
                ? <div className="p-4 text-center text-xs text-muted-foreground">{crawlStatus === 'running' ? 'Waiting for crawl to finish…' : 'Waiting for scan to start…'}</div>
                : moduleEntries.map(([name, m]) => <ModuleRow key={name} name={name} meta={m} />)}
            </div>
          </Card>

          {/* Log */}
          <Card className="overflow-hidden">
            <div className="flex items-center gap-1.5 border-b border-border px-4 py-2.5 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
              <Terminal size={12} /> Live log
            </div>
            <div ref={logsRef} className="h-56 space-y-0.5 overflow-y-auto bg-elevated p-3 font-mono text-2xs leading-relaxed">
              {logs.map((log, i) => (
                <div key={i} className="flex gap-2">
                  <span className="shrink-0 text-subtle-foreground tnum">{new Date(log.ts).toLocaleTimeString('en', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                  <span className={cn('min-w-0 break-words', LOG_COLOR[log.level] || 'text-muted-foreground')}>{log.message}</span>
                </div>
              ))}
              {running && <span className="inline-block h-3 w-1.5 animate-pulse bg-primary align-middle" />}
            </div>
          </Card>
        </div>

        {/* Right: severity + findings */}
        <div className="space-y-4">
          {/* AI analysis — exec summary + correlated attack chains */}
          {ai && (ai.summary || ai.correlations?.length > 0) && (
            <Card className="overflow-hidden border-primary/40">
              <div className="flex items-center gap-2 border-b border-border bg-primary-soft px-4 py-2.5">
                <Sparkles size={14} className="text-primary" />
                <span className="text-2xs font-semibold uppercase tracking-wider text-primary">AI Analysis</span>
              </div>
              <div className="space-y-4 p-4">
                {ai.summary && (
                  <div>
                    <div className="mb-1 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">Executive Summary</div>
                    <p className="text-sm leading-relaxed text-foreground">{ai.summary}</p>
                  </div>
                )}
                {ai.correlations?.length > 0 && (
                  <div>
                    <div className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">Correlated Attack Chains ({ai.correlations.length})</div>
                    <ul className="space-y-1.5">
                      {ai.correlations.map((c, i) => (
                        <li key={i} className="flex gap-2 text-sm leading-relaxed text-foreground">
                          <Link2 size={14} className="mt-0.5 shrink-0 text-primary" /> <span>{c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="text-2xs italic text-subtle-foreground">
                  Generated locally by an LLM from the confirmed findings. Advisory only — severity and detection are set by the scanner.
                </div>
              </div>
            </Card>
          )}

          {/* Severity summary (clickable filters) */}
          <div className="grid grid-cols-5 gap-2">
            {SEVERITIES.map(s => {
              const Icon = SEV_ICON[s]
              const active = filterSev === s
              return (
                <button key={s} onClick={() => setFilterSev(f => (f === s ? 'all' : s))}
                  className={cn('flex flex-col items-center gap-1 rounded-lg border bg-card px-2 py-3 transition-colors',
                    active ? 'border-primary ring-1 ring-primary' : 'border-border hover:border-border-strong')}>
                  <span className={cn('sev-badge border-0 bg-transparent p-0', `sev-${s}`)}><Icon size={14} /></span>
                  <span className={cn('text-lg font-semibold tnum', counts[s] ? `sev-fg-${s}` : 'text-subtle-foreground')}>{counts[s] || 0}</span>
                  <span className={cn('text-2xs capitalize', counts[s] ? `sev-fg-${s}` : 'text-muted-foreground')}>{s}</span>
                </button>
              )
            })}
          </div>

          {/* Findings table */}
          <Card className="overflow-hidden">
            <div className="flex flex-col gap-2 border-b border-border p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <span className="text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
                  Vulnerabilities ({filteredFindings.length}{filteredFindings.length !== vulnFindings.length ? `/${vulnFindings.length}` : ''})
                </span>
                {filterSev !== 'all' && (
                  <button onClick={() => setFilterSev('all')} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-2xs text-muted-foreground hover:text-foreground">
                    {filterSev} <X size={10} />
                  </button>
                )}
              </div>
              <div className="w-full sm:w-56">
                <Input icon={Search} placeholder="Search findings…" value={search} onChange={e => setSearch(e.target.value)} className="h-8 text-xs" />
              </div>
            </div>

            {vulnFindings.length === 0 ? (
              <div className="p-10 text-center text-sm text-muted-foreground">
                {isActive ? (crawlStatus === 'running' ? 'Playwright is crawling — findings appear once modules start.' : 'Scanning… vulnerabilities will appear here.') : 'No vulnerabilities detected.'}
              </div>
            ) : filteredFindings.length === 0 ? (
              <div className="p-10 text-center text-sm text-muted-foreground">No vulnerabilities match your filter.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
                      <SortTh label="Severity" field="severity" {...{ sortField, sortDir, toggleSort }} className="w-32" />
                      <SortTh label="Finding" field="title" {...{ sortField, sortDir, toggleSort }} />
                      <SortTh label="Module" field="module" {...{ sortField, sortDir, toggleSort }} className="hidden md:table-cell" />
                      <th className="px-3 py-2.5 text-right font-semibold">URLs</th>
                      <th className="w-8" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filteredFindings.map(f => (
                      <FindingRows key={f.id} finding={f}
                        expanded={!!expanded[f.id]}
                        activeTab={activeTab[f.id] || 'overview'}
                        onToggle={() => setExpanded(e => ({ ...e, [f.id]: !e[f.id] }))}
                        onTab={tab => setActiveTab(t => ({ ...t, [f.id]: tab }))} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* ── Verification — test cases confirmed safe ── */}
          {verification.length > 0 && (
            <Card className="overflow-hidden">
              <button
                onClick={() => setShowVerify(v => !v)}
                className="flex w-full items-center gap-2 px-4 py-3 text-left"
              >
                <ShieldCheck size={15} className="shrink-0 text-emerald-500" />
                <span className="text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
                  Verification — Not Vulnerable ({notVulnCount}){naCount > 0 ? ` · Not Applicable (${naCount})` : ''}
                </span>
                <span className="ml-auto text-subtle-foreground">
                  {showVerify ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                </span>
              </button>
              {showVerify && (
                <div className="divide-y divide-border border-t border-border">
                  {verification.map(v => (
                    <VerifyRow
                      key={v.module}
                      row={v}
                      expanded={!!verifyExpanded[v.module]}
                      activeTab={verifyTab[v.module] || 'overview'}
                      onToggle={() => setVerifyExpanded(e => ({ ...e, [v.module]: !e[v.module] }))}
                      onTab={tab => setVerifyTab(t => ({ ...t, [v.module]: tab }))}
                    />
                  ))}
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

/* ── Small pieces ─────────────────────────────────────── */
const LOG_COLOR = {
  success: 'text-emerald-600 dark:text-emerald-400',
  error: 'text-red-600 dark:text-red-400',
  critical: 'text-red-600 dark:text-red-400 font-semibold',
  warning: 'text-amber-600 dark:text-amber-400',
  module: 'text-primary',
  finding: 'text-foreground',
  info: 'text-muted-foreground',
  muted: 'text-subtle-foreground',
}

const URL_TAG_CLS = {
  api: 'text-violet-700 bg-violet-50 dark:text-violet-300 dark:bg-violet-500/10',
  form: 'text-amber-700 bg-amber-50 dark:text-amber-300 dark:bg-amber-500/10',
  js: 'text-sky-700 bg-sky-50 dark:text-sky-300 dark:bg-sky-500/10',
  page: 'text-slate-600 bg-slate-100 dark:text-slate-300 dark:bg-slate-500/10',
}
function UrlTag({ tag }) {
  return <span className={cn('shrink-0 rounded px-1.5 py-0.5 text-2xs font-medium uppercase', URL_TAG_CLS[tag])}>{tag}</span>
}

function ReportMenu({ id }) {
  const [open, setOpen] = useState(false)
  const formats = [['PDF', 'pdf'], ['HTML', 'html']]
  return (
    <div className="relative">
      <Button size="sm" onClick={() => setOpen(o => !o)}>
        <Download size={13} /> Report <ChevronDown size={12} className={cn('transition-transform', open && 'rotate-180')} />
      </Button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1 w-36 overflow-hidden rounded-lg border border-border bg-card shadow-pop">
            <div className="px-3 py-1.5 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">Download as</div>
            {formats.map(([label, fmt]) => (
              <a key={fmt} href={`${API}/api/report/${id}?format=${fmt}`} target="_blank" rel="noreferrer"
                 onClick={() => setOpen(false)}
                 className="flex items-center gap-2 border-t border-border px-3 py-2 text-xs text-foreground hover:bg-muted">
                <Download size={12} className="text-subtle-foreground" /> {label}
              </a>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function StatusPill({ status, isPaused, count, pending }) {
  // A user action is in flight — show it until the backend confirms over WS.
  const pendingMap = {
    pausing:  ['bg-amber-500 animate-pulse', 'Pausing…',  'text-amber-600 dark:text-amber-400'],
    resuming: ['bg-primary animate-pulse',   'Resuming…', 'text-primary'],
    stopping: ['bg-red-500 animate-pulse',   'Stopping…', 'text-red-600 dark:text-red-400'],
  }
  const map = {
    running: isPaused
      ? ['bg-amber-500', 'Paused', 'text-amber-600 dark:text-amber-400']
      : ['bg-primary animate-pulse', 'Scan in progress…', 'text-primary'],
    completed: ['bg-emerald-500', `Complete — ${count} finding${count !== 1 ? 's' : ''}`, 'text-emerald-600 dark:text-emerald-400'],
    failed: ['bg-red-500', 'Scan failed', 'text-red-600 dark:text-red-400'],
    stopped: ['bg-muted-foreground', `Stopped — ${count} finding${count !== 1 ? 's' : ''}`, 'text-muted-foreground'],
    connecting: ['bg-amber-500', 'Connecting…', 'text-amber-600 dark:text-amber-400'],
    disconnected: ['bg-muted-foreground', 'Disconnected', 'text-muted-foreground'],
  }
  const [dot, label, textCls] = (pending && pendingMap[pending]) || map[status] || map.connecting
  return (
    <div className={cn('mt-1 flex items-center gap-1.5 text-xs font-medium', textCls)}>
      <span className={cn('h-2 w-2 rounded-full', dot)} /> {label}
    </div>
  )
}

function SortTh({ label, field, sortField, sortDir, toggleSort, className }) {
  const active = sortField === field
  return (
    <th className={cn('px-3 py-2.5 font-semibold', className)}>
      <button onClick={() => toggleSort(field)} className={cn('inline-flex items-center gap-1 hover:text-foreground', active && 'text-foreground')}>
        {label} <ArrowUpDown size={11} className={active ? 'opacity-100' : 'opacity-40'} />
      </button>
    </th>
  )
}

function ModuleRow({ name, meta }) {
  const isPlaywright = meta.playwright ?? PLAYWRIGHT_MODULES.has(name)
  return (
    <div className="flex items-center gap-2 px-4 py-2">
      <span className="flex h-4 w-4 shrink-0 items-center justify-center">
        {meta.status === 'running' ? <Loader2 size={13} className="animate-spin text-primary" />
          : meta.status === 'done' ? <CheckCircle2 size={13} className="text-emerald-500" />
          : meta.status === 'error' ? <X size={13} className="text-red-500" />
          : <span className="h-1.5 w-1.5 rounded-full bg-border-strong" />}
      </span>
      <span className="flex-1 truncate text-xs text-foreground">{moduleLabel(name)}</span>
      {isPlaywright && <span className="rounded bg-muted px-1.5 py-0.5 text-2xs font-medium text-subtle-foreground">Playwright</span>}
      <span className="w-14 text-right font-mono text-2xs text-muted-foreground tnum">
        {meta.status === 'running' && meta.percent != null ? `${meta.percent}%`
          : (meta.status === 'done' || meta.status === 'error') && meta.elapsed != null ? `${meta.elapsed}s` : ''}
      </span>
      {meta.findingCount > 0 && <span className="ml-1 rounded-full bg-primary-soft px-1.5 text-2xs font-semibold text-primary tnum">{meta.findingCount}</span>}
    </div>
  )
}

function FindingRows({ finding: f, expanded, activeTab, onToggle, onTab }) {
  const isPlaywright = PLAYWRIGHT_MODULES.has(f.module)
  const tabs = ['overview', 'evidence', 'request', 'remediation']
  return (
    <>
      <tr id={`finding-${f.id}`} className="cursor-pointer transition-colors hover:bg-muted/50" onClick={onToggle}>
        <td className="px-3 py-2.5"><SeverityBadge severity={f.severity} /></td>
        <td className="px-3 py-2.5">
          <div className="font-medium text-foreground">{f.title}</div>
          <div className="mt-0.5 flex items-center gap-1.5 md:hidden">
            <span className="text-2xs text-muted-foreground">{moduleLabel(f.module)}</span>
            {isPlaywright && <span className="rounded bg-muted px-1 text-2xs text-subtle-foreground">Playwright</span>}
          </div>
        </td>
        <td className="hidden px-3 py-2.5 text-xs text-muted-foreground md:table-cell">
          {moduleLabel(f.module)}{isPlaywright && <span className="ml-1.5 rounded bg-muted px-1 text-2xs text-subtle-foreground">Playwright</span>}
        </td>
        <td className="px-3 py-2.5 text-right text-xs text-muted-foreground tnum">{f.affected_urls?.length || 0}</td>
        <td className="pr-3 text-subtle-foreground">{expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} className="bg-muted/40 px-3 pb-4 pt-1">
            <div className="animate-fade-in rounded-lg border border-border bg-card p-4">
              <div className="mb-3 flex flex-wrap gap-1 border-b border-border pb-3">
                {tabs.map(t => (
                  <button key={t} onClick={() => onTab(t)}
                    className={cn('rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors',
                      activeTab === t ? 'bg-primary-soft text-primary' : 'text-muted-foreground hover:bg-muted')}>
                    {t}
                  </button>
                ))}
              </div>
              {activeTab === 'overview' && (
                <div className="space-y-3">
                  <Field label="Description" value={f.description} />
                  {f.affected_urls?.length > 0 && (
                    <div>
                      <div className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">Affected URLs ({f.affected_urls.length})</div>
                      <div className="space-y-1">
                        {f.affected_urls.map((u, i) => <div key={i} className="break-all rounded border border-border bg-muted px-2 py-1 font-mono text-2xs text-muted-foreground">{u}</div>)}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {activeTab === 'evidence' && <Code label="Evidence" value={f.evidence} />}
              {activeTab === 'request' && <div className="space-y-3"><Code label="Request" value={f.request_data} /><Code label="Response" value={f.response_data} /></div>}
              {activeTab === 'remediation' && (
                <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm leading-relaxed text-emerald-900 dark:border-emerald-500/25 dark:bg-emerald-500/5 dark:text-emerald-200">
                  {f.remediation || 'No remediation available.'}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function VerifyRow({ row, expanded, activeTab, onToggle, onTab }) {
  const na   = row.status === 'not_applicable'
  const f    = row.finding
  const info = TESTCASE_INFO[row.module] || {}
  const tabs = ['overview', 'evidence', 'request', 'remediation']
  const passed = na
    ? 'This module did not complete — an error occurred during execution, so no result is available.'
    : 'This test case was checked and the target passed — no issue was found.'
  return (
    <>
      <button onClick={onToggle} className="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-muted/50">
        {na
          ? <MinusCircle size={15} className="shrink-0 text-subtle-foreground" />
          : <CheckCircle2 size={15} className="shrink-0 text-emerald-500" />}
        <span className="flex-1 truncate text-sm text-foreground">{row.title}</span>
        <span className="hidden text-2xs text-muted-foreground sm:inline">{moduleLabel(row.module)}</span>
        <span className={cn('text-2xs font-medium', na ? 'text-subtle-foreground' : 'text-emerald-600 dark:text-emerald-400')}>
          {na ? 'Not Applicable' : 'Not Vulnerable'}
        </span>
        <span className="text-subtle-foreground">{expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
      </button>
      {expanded && (
        <div className="animate-fade-in bg-muted/40 px-4 pb-3 pt-1">
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="mb-3 flex flex-wrap gap-1 border-b border-border pb-3">
              {tabs.map(t => (
                <button key={t} onClick={() => onTab(t)}
                  className={cn('rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors',
                    activeTab === t ? 'bg-primary-soft text-primary' : 'text-muted-foreground hover:bg-muted')}>
                  {t}
                </button>
              ))}
            </div>

            {activeTab === 'overview' && (
              <div className="space-y-3">
                <Field label="Description" value={f?.description || info.description} />
                <div>
                  <div className="mb-1 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">Result</div>
                  <div className={cn('text-sm', na ? 'text-muted-foreground' : 'text-emerald-600 dark:text-emerald-400')}>
                    {na ? 'Not Applicable' : 'Not Vulnerable'}
                  </div>
                </div>
                {f?.affected_urls?.length > 0 && (
                  <div>
                    <div className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">Checked URLs ({f.affected_urls.length})</div>
                    <div className="space-y-1">
                      {f.affected_urls.map((u, i) => <div key={i} className="break-all rounded border border-border bg-muted px-2 py-1 font-mono text-2xs text-muted-foreground">{u}</div>)}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'evidence' && (
              f?.evidence
                ? <Code label="Evidence" value={f.evidence} />
                : <div className="text-sm text-muted-foreground">{passed}</div>
            )}

            {activeTab === 'request' && (
              (f?.request_data || f?.response_data)
                ? <div className="space-y-3">
                    {f.request_data && <Code label="Request" value={f.request_data} />}
                    {f.response_data && <Code label="Response" value={f.response_data} />}
                  </div>
                : <div className="text-sm text-muted-foreground">No vulnerable request to show — {na ? 'the test case did not run.' : 'the target passed this check.'}</div>
            )}

            {activeTab === 'remediation' && (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm leading-relaxed text-emerald-900 dark:border-emerald-500/25 dark:bg-emerald-500/5 dark:text-emerald-200">
                {info.remediation || f?.remediation || 'No action required — the target is not vulnerable to this test case.'}
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}

function Field({ label, value }) {
  return (
    <div>
      <div className="mb-1 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">{label}</div>
      <div className="text-sm leading-relaxed text-foreground">{value || '—'}</div>
    </div>
  )
}
function Code({ label, value }) {
  return (
    <div>
      <div className="mb-1 text-2xs font-semibold uppercase tracking-wide text-subtle-foreground">{label}</div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-elevated p-3 font-mono text-xs text-muted-foreground">{value || '—'}</pre>
    </div>
  )
}
