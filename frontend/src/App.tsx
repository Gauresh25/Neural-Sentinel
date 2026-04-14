import { useCallback, useEffect, useState } from 'react'
import { fetchStats, fetchSummary, fetchConfidenceDist, fetchThreshold } from './api'
import { useSSE } from './hooks/useSSE'
import { Header } from './components/Header'
import { StatCard } from './components/StatCard'
import { AttackCategoryChart } from './components/AttackCategoryChart'
import { ConfidenceHistogram } from './components/ConfidenceHistogram'
import { AlertFeed } from './components/AlertFeed'
import { ThreatLookup } from './components/ThreatLookup'
import { ThresholdSlider } from './components/ThresholdSlider'
import type { Stats, SummaryData, ConfidenceData } from './types'

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [summary, setSummary] = useState<SummaryData | null>(null)
  const [confDist, setConfDist] = useState<ConfidenceData | null>(null)
  const [threshold, setThreshold] = useState(0.5)
  const alerts = useSSE(300)

  const refresh = useCallback(async () => {
    try {
      const [s, sum, conf] = await Promise.all([
        fetchStats(), fetchSummary(), fetchConfidenceDist(),
      ])
      setStats(s)
      setSummary(sum)
      setConfDist(conf)
    } catch { /* backend not ready yet */ }
  }, [])

  useEffect(() => {
    fetchThreshold().then(d => setThreshold(d.threshold)).catch(() => {})
    refresh()
    const id = setInterval(refresh, 3000)
    return () => clearInterval(id)
  }, [refresh])

  const attackPct = stats && stats.total > 0
    ? ((stats.attacks / stats.total) * 100).toFixed(1)
    : '0.0'

  return (
    <div className="min-h-screen bg-[#080b14] text-slate-200 p-4 space-y-3">
      <Header stats={stats} />

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard
          label="Total Flows"
          value={stats?.total ?? 0}
          sub="since start"
        />
        <StatCard
          label="Attacks"
          value={stats?.attacks ?? 0}
          variant="attack"
          sub={`${attackPct}% of traffic`}
        />
        <StatCard
          label="Normal"
          value={stats?.normal ?? 0}
          variant="normal"
        />
        <StatCard
          label="Attack Rate"
          value={(stats?.attack_rate ?? 0).toFixed(1)}
          unit="atk/min"
          variant="warn"
          sub="rolling average"
        />
      </div>

      {/* Threshold slider */}
      <ThresholdSlider threshold={threshold} onChange={setThreshold} />

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-3">
        <AttackCategoryChart data={summary} />
        <ConfidenceHistogram data={confDist} threshold={threshold} />
      </div>

      {/* Feed + Lookup row */}
      <div className="grid grid-cols-2 gap-3">
        <AlertFeed alerts={alerts} />
        <ThreatLookup />
      </div>
    </div>
  )
}
