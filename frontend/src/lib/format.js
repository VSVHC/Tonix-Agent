/** Parse a backend timestamp. Old rows are naive UTC ("...123456");
 *  newer rows are tz-aware ("...+00:00"). Only append 'Z' when there's
 *  no timezone marker so both parse as UTC. Returns null on failure. */
export function parseUTC(iso) {
  if (!iso) return null
  const s = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + 'Z'
  const d = new Date(s)
  return isNaN(d.getTime()) ? null : d
}

export function fmtDateTime(iso) {
  const d = parseUTC(iso)
  if (!d) return '—'
  return d.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

export function fmtDate(iso) {
  const d = parseUTC(iso)
  if (!d) return '—'
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
}

export function host(url) {
  try { return new URL(url).hostname } catch { return (url || '').replace(/^https?:\/\//, '') }
}

export function moduleLabel(name) {
  return (name || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}
