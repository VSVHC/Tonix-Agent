import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Clock, RefreshCw, Download, ExternalLink, CheckCircle2, XCircle,
  Loader2, Trash2, StopCircle, PauseCircle,
} from 'lucide-react'
import { Button, Card, IconButton, EmptyState, Skeleton, cn } from '../components/ui.jsx'
import { API } from '../lib/api.js'
import { fmtDateTime, host } from '../lib/format.js'

const STATUS_META = {
  completed: { icon: CheckCircle2, color: 'text-emerald-600 dark:text-emerald-400', label: 'Completed' },
  running:   { icon: Loader2,      color: 'text-primary', label: 'Running', spin: true },
  paused:    { icon: PauseCircle,  color: 'text-amber-600 dark:text-amber-400', label: 'Paused' },
  failed:    { icon: XCircle,      color: 'text-red-600 dark:text-red-400', label: 'Failed' },
  stopped:   { icon: StopCircle,   color: 'text-red-600 dark:text-red-400', label: 'Stopped' },
}

export default function History() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [rerunId, setRerunId] = useState(null)
  const navigate = useNavigate()

  useEffect(() => { loadHistory() }, [])

  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'running' || s.status === 'paused')
    if (!hasActive) return
    const timer = setInterval(loadHistory, 5000)
    return () => clearInterval(timer)
  }, [scans])

  async function loadHistory() {
    try {
      const res = await fetch(`${API}/api/scan/history`)
      const data = await res.json()
      setScans(data.scans || [])
    } catch {}
    setLoading(false)
  }

  async function rerun(scan) {
    setRerunId(scan.id)
    try {
      const res = await fetch(`${API}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: scan.target_url }),
      })
      const data = await res.json()
      navigate(`/scan/${data.scan_id}`)
    } catch { setRerunId(null) }
  }

  async function deleteScan(scanId) {
    if (!window.confirm('Delete this scan and all its findings? This cannot be undone.')) return
    await fetch(`${API}/api/scan/${scanId}`, { method: 'DELETE' })
    loadHistory()
  }

  return (
    <div className="animate-fade-in space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">Scan history</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {loading ? 'Loading…' : `${scans.length} scan${scans.length !== 1 ? 's' : ''} recorded`}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadHistory}>
          <RefreshCw size={14} /> Refresh
        </Button>
      </div>

      {loading ? (
        <Card className="divide-y divide-border">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="flex items-center gap-4 p-4">
              <Skeleton className="h-4 w-4 rounded-full" />
              <Skeleton className="h-4 w-48" />
              <Skeleton className="ml-auto h-4 w-24" />
            </div>
          ))}
        </Card>
      ) : scans.length === 0 ? (
        <EmptyState
          icon={Clock}
          title="No scans yet"
          description="Start your first scan from the Dashboard to see it here."
          action={<Button size="sm" onClick={() => navigate('/')}>New scan</Button>}
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
                  <th className="px-4 py-3 font-semibold">Target</th>
                  <th className="px-4 py-3 font-semibold">Status</th>
                  <th className="px-4 py-3 font-semibold">Started</th>
                  <th className="px-4 py-3 font-semibold">Findings</th>
                  <th className="px-4 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map(scan => {
                  const sm = STATUS_META[scan.status] || STATUS_META.stopped
                  const StatusIcon = sm.icon
                  const showFindings = ['completed', 'stopped', 'paused'].includes(scan.status)
                  return (
                    <tr key={scan.id} className="group transition-colors hover:bg-muted/50">
                      <td className="px-4 py-3">
                        <button
                          onClick={() => navigate(`/scan/${scan.id}`)}
                          className="font-mono text-sm text-foreground hover:text-primary hover:underline"
                        >
                          {host(scan.target_url)}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn('inline-flex items-center gap-1.5 text-xs font-medium', sm.color)}>
                          <StatusIcon size={14} className={cn(sm.spin && 'animate-spin')} /> {sm.label}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-muted-foreground tnum">
                        {fmtDateTime(scan.started_at)}
                      </td>
                      <td className="px-4 py-3">
                        {showFindings ? (
                          <span className="text-sm font-medium text-foreground tnum">
                            {scan.total_findings || 0}
                            <span className="ml-1 text-xs font-normal text-muted-foreground">
                              finding{scan.total_findings === 1 ? '' : 's'}
                            </span>
                          </span>
                        ) : (
                          <span className="text-xs text-subtle-foreground">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-0.5 opacity-70 transition-opacity group-hover:opacity-100">
                          <IconButton title="View scan" onClick={() => navigate(`/scan/${scan.id}`)}>
                            <ExternalLink size={15} />
                          </IconButton>
                          {scan.status === 'completed' && (
                            <IconButton title="Download report" onClick={() => window.open(`${API}/api/report/${scan.id}`, '_blank')}>
                              <Download size={15} />
                            </IconButton>
                          )}
                          <IconButton title="Re-run scan" disabled={rerunId === scan.id} onClick={() => rerun(scan)}>
                            {rerunId === scan.id ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />}
                          </IconButton>
                          <IconButton title="Delete scan" className="hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-500/10" onClick={() => deleteScan(scan.id)}>
                            <Trash2 size={15} />
                          </IconButton>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
