import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid, PieChart, Pie, Cell,
} from 'recharts'
import {
  BarChart3, TrendingUp, ShieldAlert, ShieldCheck, Target, Zap, RefreshCw,
} from 'lucide-react'
import { Button, Card, CardHeader, StatCard, EmptyState, Skeleton, SeverityBadge } from '../components/ui.jsx'
import { API, SEV_COLOR, SEV_LABEL } from '../lib/api.js'
import { host, fmtDate } from '../lib/format.js'

function useChartTheme() {
  // Recharts needs concrete colors; read them from the CSS tokens so charts
  // follow the active light/dark theme.
  const get = (v, fb) => {
    if (typeof window === 'undefined') return fb
    return getComputedStyle(document.documentElement).getPropertyValue(v).trim() || fb
  }
  return {
    grid: get('--border', '#e4e7ec'),
    axis: get('--text-3', '#98a2b3'),
    tooltipBg: get('--surface', '#fff'),
    tooltipBorder: get('--border-strong', '#d0d5dd'),
    text: get('--text', '#101828'),
  }
}

export default function Analytics() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()
  const t = useChartTheme()

  const tooltipStyle = {
    background: t.tooltipBg, border: `1px solid ${t.tooltipBorder}`,
    borderRadius: 8, fontSize: 12, color: t.text, boxShadow: 'var(--shadow-pop)',
  }

  useEffect(() => {
    fetch(`${API}/api/scan/history`)
      .then(r => r.json())
      .then(d => { setScans(d.scans || []); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  const Header = () => (
    <div className="flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Analytics</h1>
        <p className="mt-1 text-sm text-muted-foreground">Scan trends and vulnerability insights</p>
      </div>
      <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
        <RefreshCw size={14} /> Refresh
      </Button>
    </div>
  )

  if (loading) {
    return (
      <div className="animate-fade-in space-y-6">
        <Header />
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-20" />)}
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    )
  }

  const completed = scans.filter(s => s.status === 'completed')

  if (scans.length === 0) {
    return (
      <div className="animate-fade-in space-y-6">
        <Header />
        <EmptyState
          icon={BarChart3}
          title="No scan data yet"
          description="Run your first scan from the Dashboard to see analytics here."
          action={<Button size="sm" onClick={() => navigate('/')}><Zap size={14} /> Start a scan</Button>}
        />
      </div>
    )
  }

  // Metrics
  const sum = (k) => completed.reduce((a, s) => a + (s[k] || 0), 0)
  const totalFindings = sum('total_findings')
  const totalCritical = sum('critical_count')
  const avgFindings = completed.length ? Math.round(totalFindings / completed.length) : 0
  const cleanScans = completed.filter(s => s.total_findings === 0).length
  const hostList = completed.map(s => host(s.target_url))
  const mostScanned = hostList.length
    ? Object.entries(hostList.reduce((a, h) => (a[h] = (a[h] || 0) + 1, a), {})).sort((a, b) => b[1] - a[1])[0][0]
    : '—'

  const severityData = ['critical', 'high', 'medium', 'low', 'info'].map(k => ({
    name: SEV_LABEL[k], key: k, value: sum(`${k}_count`), color: SEV_COLOR[k],
  }))
  const pieData = severityData.filter(d => d.value > 0)

  const timeData = [...completed].reverse().slice(-20).map((s, i) => ({
    idx: i + 1, label: host(s.target_url).slice(0, 16),
    total: s.total_findings || 0, critical: s.critical_count || 0, high: s.high_count || 0,
  }))

  const hostCounts = completed.reduce((a, s) => { const h = host(s.target_url); a[h] = (a[h] || 0) + 1; return a }, {})
  const hostData = Object.entries(hostCounts).sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([name, count]) => ({ name: name.length > 22 ? name.slice(0, 20) + '…' : name, count }))

  const outcomeData = [
    { name: 'Completed', value: completed.length, color: '#22c55e' },
    { name: 'Stopped', value: scans.filter(s => s.status === 'stopped').length, color: '#eab308' },
    { name: 'Failed', value: scans.filter(s => s.status === 'failed').length, color: '#ef4444' },
    { name: 'Active', value: scans.filter(s => s.status === 'running' || s.status === 'paused').length, color: '#3b82f6' },
  ].filter(d => d.value > 0)

  return (
    <div className="animate-fade-in space-y-6">
      <Header />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard icon={Target} label="Total scans" value={scans.length} tone="primary" />
        <StatCard icon={ShieldAlert} label="Critical found" value={totalCritical} tone="critical" />
        <StatCard icon={TrendingUp} label="Avg findings" value={avgFindings} tone="high" />
        <StatCard icon={ShieldCheck} label="Clean scans" value={cleanScans} tone="low" />
        <StatCard icon={Zap} label="Total findings" value={totalFindings} />
        <StatCard icon={Target} label="Most scanned" value={mostScanned} small />
      </div>

      {/* Row 1: severity bar + mix */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Findings by severity" />
          <div className="p-4 pt-2">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={severityData} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                <CartesianGrid stroke={t.grid} strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: t.axis }} axisLine={{ stroke: t.grid }} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: t.axis }} allowDecimals={false} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(127,127,127,.06)' }} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={64}>
                  {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <CardHeader title="Overall severity mix" />
          <div className="p-4 pt-2">
            {pieData.length === 0 ? (
              <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">No findings yet.</div>
            ) : (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="55%" height={200}>
                  <PieChart>
                    <Pie data={pieData} cx="50%" cy="50%" innerRadius={52} outerRadius={80} paddingAngle={3} dataKey="value">
                      {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-2">
                  {pieData.map(d => (
                    <div key={d.name} className="flex items-center gap-2 text-sm">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: d.color }} />
                      <span className="flex-1 text-muted-foreground">{d.name}</span>
                      <span className="font-medium text-foreground tnum">{d.value}</span>
                      <span className="w-10 text-right text-xs text-subtle-foreground tnum">
                        {totalFindings > 0 ? Math.round(d.value / totalFindings * 100) : 0}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Row 2: over time */}
      {timeData.length > 1 && (
        <Card>
          <CardHeader title="Findings over time" subtitle={`Last ${timeData.length} scans`} />
          <div className="p-4 pt-2">
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={timeData} margin={{ top: 8, right: 12, bottom: 0, left: -18 }}>
                <CartesianGrid stroke={t.grid} strokeDasharray="3 3" />
                <XAxis dataKey="label" tick={{ fontSize: 10, fill: t.axis }} interval="preserveStartEnd" axisLine={{ stroke: t.grid }} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: t.axis }} allowDecimals={false} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} dot={false} name="Total" />
                <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} name="Critical" />
                <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} name="High" />
              </LineChart>
            </ResponsiveContainer>
            <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              {[['Total', '#3b82f6'], ['Critical', '#ef4444'], ['High', '#f97316']].map(([n, c]) => (
                <div key={n} className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: c }} /> {n}
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}

      {/* Row 3: hosts + outcomes */}
      <div className="grid gap-4 lg:grid-cols-2">
        {hostData.length > 0 && (
          <Card>
            <CardHeader title="Most scanned targets" />
            <div className="p-4 pt-2">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={hostData} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 4 }}>
                  <CartesianGrid stroke={t.grid} strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 11, fill: t.axis }} allowDecimals={false} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="name" width={130} tick={{ fontSize: 11, fill: t.axis }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(127,127,127,.06)' }} />
                  <Bar dataKey="count" radius={[0, 6, 6, 0]} fill="#2563eb" maxBarSize={22} name="Scans" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        )}

        <Card>
          <CardHeader title="Scan outcomes" />
          <div className="p-4 pt-2">
            {outcomeData.length === 0 ? (
              <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">No data.</div>
            ) : (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width="55%" height={200}>
                  <PieChart>
                    <Pie data={outcomeData} cx="50%" cy="50%" innerRadius={52} outerRadius={80} paddingAngle={3} dataKey="value">
                      {outcomeData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex-1 space-y-2">
                  {outcomeData.map(d => (
                    <div key={d.name} className="flex items-center gap-2 text-sm">
                      <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: d.color }} />
                      <span className="flex-1 text-muted-foreground">{d.name}</span>
                      <span className="font-medium text-foreground tnum">{d.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Recent table */}
      {completed.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader title="Recent completed scans" />
          <div className="mt-2 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-y border-border text-left text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">
                  <th className="px-4 py-2.5 font-semibold">Target</th>
                  <th className="px-4 py-2.5 font-semibold">Date</th>
                  <th className="px-4 py-2.5 font-semibold">Severity</th>
                  <th className="px-4 py-2.5 text-right font-semibold">Total</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {completed.slice(0, 12).map(s => (
                  <tr key={s.id} className="cursor-pointer transition-colors hover:bg-muted/50" onClick={() => navigate(`/scan/${s.id}`)}>
                    <td className="px-4 py-2.5 font-mono text-xs text-foreground">{host(s.target_url)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground tnum">{fmtDate(s.started_at)}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {s.critical_count > 0 && <SeverityBadge severity="critical" />}
                        {s.high_count > 0 && <SeverityBadge severity="high" />}
                        {s.medium_count > 0 && <SeverityBadge severity="medium" />}
                        {s.low_count > 0 && <SeverityBadge severity="low" />}
                        {s.info_count > 0 && <SeverityBadge severity="info" />}
                        {s.total_findings === 0 && <span className="text-xs text-emerald-600 dark:text-emerald-400">Clean</span>}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-right font-medium text-foreground tnum">{s.total_findings || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
