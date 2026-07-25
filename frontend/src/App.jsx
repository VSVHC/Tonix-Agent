import { Routes, Route, useLocation } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import LiveScan from './pages/LiveScan.jsx'
import History from './pages/History.jsx'
import Analytics from './pages/Analytics.jsx'
import JwtTesting from './pages/JwtTesting.jsx'
import { useTheme } from './lib/theme.js'
import { API } from './lib/api.js'

export default function App() {
  const location = useLocation()
  const { theme, toggle } = useTheme()
  const [health, setHealth] = useState(null)
  const [activeScanId, setActiveScanId] = useState(null)

  const handleScanStarted = useCallback((scanId) => setActiveScanId(scanId), [])
  const handleScanEnded = useCallback(() => {}, [])

  useEffect(() => {
    const check = () =>
      fetch(`${API}/api/health`)
        .then(r => r.json())
        .then(setHealth)
        .catch(() => setHealth({ status: 'error' }))
    check()
    const t = setInterval(check, 30_000)
    return () => clearInterval(t)
  }, [])

  // Restore active scan on direct link / refresh
  useEffect(() => {
    const match = location.pathname.match(/^\/scan\/([^/]+)$/)
    if (match && !activeScanId) setActiveScanId(match[1])
  }, []) // once on mount

  const isOnLiveScan = location.pathname.startsWith('/scan/')

  return (
    <div className="flex h-dvh overflow-hidden bg-background text-foreground">
      <Sidebar activeScanId={activeScanId} health={health} theme={theme} onToggleTheme={toggle} />

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1400px] px-6 py-6 lg:px-8">
          {/* LiveScan stays mounted across navigation to keep its WebSocket alive */}
          {activeScanId && (
            <div style={{ display: isOnLiveScan ? 'block' : 'none' }}>
              <LiveScan key={activeScanId} scanId={activeScanId} onScanEnded={handleScanEnded} />
            </div>
          )}

          <Routes>
            <Route path="/" element={<Dashboard onScanStarted={handleScanStarted} />} />
            <Route path="/scan/:id" element={null} />
            <Route path="/history" element={<History />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/tools/jwt" element={<JwtTesting />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
