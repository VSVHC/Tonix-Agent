export const API = 'http://localhost:8000'
export const WS  = 'ws://localhost:8000'

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
export const SEV_LABEL  = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

// Solid tones used for charts / accent bars (readable on light and dark).
export const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
}

// Modules that run against Katana-discovered URLs (mirrors backend).
export const KATANA_MODULES = new Set([
  'clickjacking', 'trace', 'host_header',
  'http_bypass', 'error_exceptions', 'req_splitting', 'res_splitting', 'cors',
])
