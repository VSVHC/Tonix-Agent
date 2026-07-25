/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  // Severity classes are applied via template strings (e.g. `sev-${s}`), which
  // Tailwind's content scanner can't see — keep them so their colors survive.
  safelist: [
    { pattern: /^sev-(critical|high|medium|low|info)$/ },
    { pattern: /^sev-fg-(critical|high|medium|low|info)$/ },
    { pattern: /^sev-bar-(critical|high|medium|low|info)$/ },
  ],
  theme: {
    extend: {
      colors: {
        background:          'var(--bg)',
        elevated:            'var(--bg-elevated)',
        foreground:          'var(--text)',
        card:                'var(--surface)',
        muted:               'var(--surface-2)',
        'muted-foreground':  'var(--text-2)',
        'subtle-foreground': 'var(--text-3)',
        border:              'var(--border)',
        'border-strong':     'var(--border-strong)',
        ring:                'var(--ring)',
        primary: {
          DEFAULT:    'var(--primary)',
          foreground: 'var(--primary-fg)',
          hover:      'var(--primary-hover)',
          soft:       'var(--primary-soft)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      borderRadius: {
        xl: '0.75rem',
        '2xl': '1rem',
      },
      boxShadow: {
        card:  'var(--shadow-card)',
        pop:   'var(--shadow-pop)',
      },
      keyframes: {
        'fade-in':   { from: { opacity: 0, transform: 'translateY(4px)' }, to: { opacity: 1, transform: 'none' } },
        'indeterminate': { '0%': { transform: 'translateX(-100%)' }, '100%': { transform: 'translateX(400%)' } },
      },
      animation: {
        'fade-in': 'fade-in 0.2s ease-out both',
        'indeterminate': 'indeterminate 1.1s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
