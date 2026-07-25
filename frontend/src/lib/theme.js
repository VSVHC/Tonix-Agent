import { useEffect, useState } from 'react'

/**
 * Light-default theme with a persisted toggle.
 * The `dark` class on <html> drives Tailwind's dark: variants.
 * index.html applies the saved theme before first paint (no flash).
 */
export function useTheme() {
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('theme') || 'light' } catch { return 'light' }
  })

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('dark', theme === 'dark')
    try { localStorage.setItem('theme', theme) } catch {}
    const meta = document.querySelector('meta[name="theme-color"]')
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#0b0f16' : '#ffffff')
  }, [theme])

  return { theme, setTheme, toggle: () => setTheme(t => (t === 'dark' ? 'light' : 'dark')) }
}
