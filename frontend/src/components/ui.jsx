import { AlertOctagon, AlertTriangle, AlertCircle, ShieldCheck, Info, Loader2 } from 'lucide-react'
import { SEV_LABEL } from '../lib/api.js'

/* ── Class helper ─────────────────────────────────────── */
export function cn(...parts) {
  return parts.filter(Boolean).join(' ')
}

/* ── Button ───────────────────────────────────────────── */
const BTN_BASE =
  'inline-flex items-center justify-center gap-1.5 rounded-lg font-medium ' +
  'transition-colors focus-visible:outline-none disabled:opacity-50 disabled:pointer-events-none select-none'

const BTN_SIZES = {
  sm: 'h-8 px-3 text-xs',
  md: 'h-9 px-4 text-sm',
  lg: 'h-11 px-5 text-sm',
  xl: 'h-14 px-7 text-base',
}

const BTN_VARIANTS = {
  primary: 'bg-primary text-primary-foreground hover:bg-primary-hover shadow-sm',
  secondary: 'bg-muted text-foreground hover:bg-border border border-border',
  outline: 'border border-border text-foreground hover:bg-muted',
  ghost: 'text-muted-foreground hover:text-foreground hover:bg-muted',
  danger: 'bg-red-600 text-white hover:bg-red-700 shadow-sm',
}

export function Button({ variant = 'primary', size = 'md', className, as, href, children, ...props }) {
  const cls = cn(BTN_BASE, BTN_SIZES[size], BTN_VARIANTS[variant], className)
  if (as === 'a' || href) {
    return <a href={href} className={cls} {...props}>{children}</a>
  }
  return <button className={cls} {...props}>{children}</button>
}

export function IconButton({ className, title, children, ...props }) {
  return (
    <button
      title={title}
      aria-label={title}
      className={cn(
        'inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground',
        'transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none',
        'disabled:opacity-50 disabled:pointer-events-none',
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
}

/* ── Card ─────────────────────────────────────────────── */
export function Card({ className, children, ...props }) {
  return <div className={cn('card', className)} {...props}>{children}</div>
}

export function CardHeader({ title, subtitle, right, className }) {
  return (
    <div className={cn('flex items-start justify-between gap-3 px-5 pt-4', className)}>
      <div>
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
        {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
      </div>
      {right}
    </div>
  )
}

export function SectionLabel({ children, className }) {
  return (
    <div className={cn('text-2xs font-semibold uppercase tracking-wider text-subtle-foreground', className)}>
      {children}
    </div>
  )
}

/* ── Severity ─────────────────────────────────────────── */
export const SEV_ICON = {
  critical: AlertOctagon,
  high: AlertTriangle,
  medium: AlertCircle,
  low: ShieldCheck,
  info: Info,
}

export function SeverityBadge({ severity, className }) {
  const Icon = SEV_ICON[severity] || Info
  return (
    <span className={cn('sev-badge', `sev-${severity}`, className)}>
      <Icon size={11} strokeWidth={2.4} />
      {SEV_LABEL[severity] || severity}
    </span>
  )
}

/* ── Input ────────────────────────────────────────────── */
export function Input({ className, icon: Icon, ...props }) {
  return (
    <div className="relative">
      {Icon && (
        <Icon size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle-foreground" />
      )}
      <input
        className={cn(
          'h-9 w-full rounded-lg border border-border bg-elevated text-sm text-foreground',
          'placeholder:text-subtle-foreground transition-colors',
          'focus:border-primary focus:outline-none focus:ring-2 focus:ring-ring/50',
          Icon ? 'pl-9 pr-3' : 'px-3',
          className,
        )}
        {...props}
      />
    </div>
  )
}

/* ── Feedback ─────────────────────────────────────────── */
export function Spinner({ size = 16, className }) {
  return <Loader2 size={size} className={cn('animate-spin', className)} />
}

export function Skeleton({ className }) {
  return <div className={cn('animate-pulse rounded-lg bg-muted', className)} />
}

export function EmptyState({ icon: Icon, title, description, action, className }) {
  return (
    <div className={cn('flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card px-6 py-14 text-center', className)}>
      {Icon && (
        <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Icon size={20} />
        </div>
      )}
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ProgressBar({ value = 0, indeterminate = false, className }) {
  return (
    <div className={cn('relative h-1.5 w-full overflow-hidden rounded-full bg-muted', className)}>
      {indeterminate ? (
        <div className="absolute inset-y-0 w-1/4 animate-indeterminate rounded-full bg-primary" />
      ) : (
        <div
          className="h-full rounded-full bg-primary transition-[width] duration-500 ease-out"
          style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
        />
      )}
    </div>
  )
}

/* ── Stat card ────────────────────────────────────────── */
export function StatCard({ icon: Icon, label, value, tone = 'default', small }) {
  const tones = {
    default:  'text-muted-foreground',
    primary:  'text-primary',
    critical: 'text-red-600 dark:text-red-400',
    high:     'text-orange-600 dark:text-orange-400',
    low:      'text-emerald-600 dark:text-emerald-400',
  }
  return (
    <div className="card flex flex-col gap-2 p-4">
      <div className="flex items-center gap-2">
        <span className={cn('flex h-7 w-7 items-center justify-center rounded-md bg-muted', tones[tone])}>
          {Icon && <Icon size={15} />}
        </span>
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
      </div>
      <div className={cn('tnum font-semibold text-foreground', small ? 'text-base' : 'text-2xl')}>{value}</div>
    </div>
  )
}
