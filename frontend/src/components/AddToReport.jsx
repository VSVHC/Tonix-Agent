import { useState, useEffect } from 'react'
import { FileText, CheckCircle2, Download } from 'lucide-react'
import { Button, Card, CardHeader, Spinner } from './ui.jsx'
import { API } from '../lib/api.js'
import { host, fmtDate } from '../lib/format.js'

/**
 * Attach a manual tool result (JWT) to an existing scan's report.
 * Shows a picker of completed scans; on submit the backend saves the result
 * as a finding for that scan; the report picks it up on next download.
 */
export default function AddToReport({ tool, result }) {
  const [scans, setScans] = useState(null)   // null = loading
  const [scanId, setScanId] = useState('')
  const [state, setState] = useState('idle') // idle | saving | done | error
  const [msg, setMsg] = useState('')

  useEffect(() => {
    fetch(`${API}/api/scan/history`)
      .then(r => r.json())
      .then(d => {
        const done = (d.scans || []).filter(s => s.status === 'completed')
        setScans(done)
        if (done[0]) setScanId(done[0].id)
      })
      .catch(() => setScans([]))
  }, [])

  const attach = async () => {
    setState('saving'); setMsg('')
    try {
      const r = await fetch(`${API}/api/tools/attach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, tool, result }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || `Failed (${r.status})`)
      setState('done'); setMsg('Added — the scan report has been regenerated.')
    } catch (e) {
      setState('error'); setMsg(e.message)
    }
  }

  return (
    <Card>
      <CardHeader
        title={<span className="flex items-center gap-2"><FileText size={15} /> Add to a scan report</span>}
        subtitle="Attach this result to a completed scan; its PDF/HTML/XML report is regenerated to include it."
      />
      <div className="p-5 pt-3">
        {scans === null ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground"><Spinner size={14} /> Loading scans…</div>
        ) : scans.length === 0 ? (
          <p className="text-xs text-subtle-foreground">
            No completed scans yet. Run a scan from the Dashboard first, then come back to attach this result to its report.
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={scanId}
              onChange={e => { setScanId(e.target.value); setState('idle'); setMsg('') }}
              className="h-9 rounded-lg border border-border bg-elevated px-3 text-sm text-foreground focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring/50"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>{host(s.target_url)} · {fmtDate(s.started_at)}</option>
              ))}
            </select>
            <Button size="sm" onClick={attach} disabled={state === 'saving' || !scanId}>
              {state === 'saving' ? <Spinner size={14} /> : <FileText size={14} />} Add to report
            </Button>
            {state === 'done' && (
              <>
                <span className="flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 size={14} /> {msg}
                </span>
                <a
                  className="inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                  href={`${API}/api/report/${scanId}?format=pdf`} target="_blank" rel="noreferrer"
                >
                  <Download size={13} /> Download PDF
                </a>
              </>
            )}
            {state === 'error' && <span className="text-xs text-red-600 dark:text-red-400">{msg}</span>}
          </div>
        )}
      </div>
    </Card>
  )
}
