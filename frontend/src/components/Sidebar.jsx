import { NavLink } from 'react-router-dom'
import { useEffect, useState } from 'react'
import {
  Shield, LayoutDashboard, Activity, Clock, BarChart3, KeyRound,
  PanelLeftClose, PanelLeftOpen, Sun, Moon, Circle,
} from 'lucide-react'
import { cn } from './ui.jsx'

function NavItem({ to, icon: Icon, label, collapsed, live, end }) {
  return (
    <NavLink
      to={to}
      end={end}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        cn(
          'group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
          collapsed && 'justify-center px-0',
          isActive
            ? 'bg-primary-soft text-primary'
            : 'text-muted-foreground hover:bg-muted hover:text-foreground',
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive && !collapsed && (
            <span className="absolute left-0 top-1/2 h-5 -translate-y-1/2 rounded-r-full bg-primary" style={{ width: 3 }} />
          )}
          <Icon size={18} strokeWidth={2} className="shrink-0" />
          {!collapsed && <span className="flex-1">{label}</span>}
          {!collapsed && live && (
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" style={{ boxShadow: '0 0 0 3px rgba(16,185,129,.18)' }} />
          )}
        </>
      )}
    </NavLink>
  )
}

function HealthRow({ label, ok, okText, badText, collapsed }) {
  return (
    <div className={cn('flex items-center gap-2 text-xs', collapsed && 'justify-center')}>
      <Circle size={8} className={ok ? 'fill-emerald-500 text-emerald-500' : 'fill-amber-500 text-amber-500'} />
      {!collapsed && (
        <span className="text-muted-foreground">
          {label} <span className={ok ? 'text-foreground' : 'text-amber-600 dark:text-amber-400'}>{ok ? okText : badText}</span>
        </span>
      )}
    </div>
  )
}

export default function Sidebar({ activeScanId, health, theme, onToggleTheme }) {
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem('sidebar-collapsed') === '1' } catch { return false }
  })
  useEffect(() => {
    try { localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0') } catch {}
  }, [collapsed])

  const ollamaOk = health?.ollama === 'connected'
  const dbOk = health?.database === 'connected'

  return (
    <aside
      className={cn(
        'flex shrink-0 flex-col border-r border-border bg-card transition-[width] duration-200',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      {/* Brand */}
      <div className={cn('flex h-16 items-center gap-2.5 border-b border-border px-4', collapsed && 'justify-center px-0')}>
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <Shield size={17} strokeWidth={2.5} />
        </div>
        {!collapsed && (
          <div className="leading-tight">
            <div className="text-sm font-semibold text-foreground">Tonix Agent</div>
            <div className="text-2xs text-subtle-foreground">Security Scanner</div>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-1 p-3">
        {!collapsed && <div className="px-3 pb-1 pt-2 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">Workspace</div>}
        <NavItem to="/" end icon={LayoutDashboard} label="Dashboard" collapsed={collapsed} />
        {activeScanId && (
          <NavItem to={`/scan/${activeScanId}`} icon={Activity} label="Live Scan" collapsed={collapsed} live />
        )}
        <NavItem to="/history" icon={Clock} label="History" collapsed={collapsed} />
        <NavItem to="/analytics" icon={BarChart3} label="Analytics" collapsed={collapsed} />

        {collapsed
          ? <div className="mx-2 my-3 border-t border-border" />
          : <div className="px-3 pb-1 pt-4 text-2xs font-semibold uppercase tracking-wider text-subtle-foreground">Security Tools</div>}
        <NavItem to="/tools/jwt" icon={KeyRound} label="JWT Analysis" collapsed={collapsed} />
      </nav>

      {/* Footer: health + theme + collapse */}
      <div className="space-y-3 border-t border-border p-3">
        <div className={cn('space-y-1.5', !collapsed && 'px-2')}>
          <HealthRow label="Ollama" ok={ollamaOk} okText="ready" badText="offline" collapsed={collapsed} />
          <HealthRow label="Database" ok={dbOk} okText="connected" badText="error" collapsed={collapsed} />
        </div>

        <div className={cn('flex items-center gap-1', collapsed ? 'flex-col' : 'justify-between')}>
          <button
            onClick={onToggleTheme}
            title={theme === 'dark' ? 'Switch to light' : 'Switch to dark'}
            aria-label="Toggle theme"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button
            onClick={() => setCollapsed(c => !c)}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label="Toggle sidebar"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </div>
      </div>
    </aside>
  )
}
