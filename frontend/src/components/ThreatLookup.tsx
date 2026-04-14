import { useState } from 'react'
import { fetchThreat } from '../api'
import type { ThreatData } from '../types'

const CAT_BADGE: Record<string, string> = {
  'DoS': 'badge-attack', 'Reconnaissance': 'badge-warn',
  'Brute Force (SSH)': 'badge-attack', 'Backdoor': 'badge-purple',
  'Normal': 'badge-normal',
}

export function ThreatLookup() {
  const [ip, setIp] = useState('')
  const [data, setData] = useState<ThreatData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const lookup = async () => {
    const query = ip.trim()
    if (!query) return
    setLoading(true)
    setError('')
    try {
      const d: ThreatData = await fetchThreat(query)
      setData(d)
    } catch {
      setError('Lookup failed')
    } finally {
      setLoading(false)
    }
  }

  const attackPct = data
    ? data.summary.total > 0
      ? Math.round((data.summary.attacks / data.summary.total) * 100)
      : 0
    : 0

  return (
    <div className="card flex flex-col" style={{ minHeight: 340 }}>
      <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase mb-3 shrink-0">
        IP Threat Lookup
      </div>

      {/* Search bar */}
      <div className="flex gap-2 shrink-0 mb-4">
        <input
          value={ip}
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && lookup()}
          placeholder="192.168.1.100"
          className="flex-1 bg-[#0d1117] border border-[#1c2333] rounded-md px-3 py-1.5
                     text-xs text-slate-200 placeholder-slate-600
                     focus:outline-none focus:border-[#263249] transition"
        />
        <button
          onClick={lookup}
          disabled={loading}
          className="px-4 py-1.5 rounded-md text-xs font-semibold tracking-wider
                     bg-[#1c2333] hover:bg-[#263249] text-slate-300 transition
                     disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading ? '...' : 'LOOKUP'}
        </button>
      </div>

      {error && <p className="text-[#ff2d55] text-xs mb-2">{error}</p>}

      {/* Results */}
      {data && (
        <div className="flex-1 overflow-y-auto space-y-4">
          {/* Summary header */}
          <div className="bg-[#0d1117] rounded-lg p-3 space-y-2">
            <div className="text-xs text-slate-300 font-semibold">{data.ip}</div>
            <div className="grid grid-cols-3 gap-2 text-center">
              {[
                { label: 'TOTAL', val: data.summary.total, color: 'text-slate-300' },
                { label: 'ATTACKS', val: data.summary.attacks, color: 'text-[#ff2d55]' },
                { label: 'ATK %', val: `${attackPct}%`, color: attackPct > 50 ? 'text-[#ff2d55]' : 'text-[#00ff88]' },
              ].map(item => (
                <div key={item.label}>
                  <div className={`text-lg font-bold ${item.color}`}>{item.val}</div>
                  <div className="text-[9px] text-slate-600 tracking-widest">{item.label}</div>
                </div>
              ))}
            </div>

            {/* Direction split */}
            <div className="flex gap-2 text-[10px]">
              <span className="text-slate-500">as src:</span>
              <span className="text-slate-300">{data.summary.as_src}</span>
              <span className="text-slate-500 ml-2">as dst:</span>
              <span className="text-slate-300">{data.summary.as_dst}</span>
            </div>

            {/* Category badges */}
            {Object.keys(data.summary.categories).length > 0 && (
              <div className="flex flex-wrap gap-1 pt-1">
                {Object.entries(data.summary.categories).map(([cat, cnt]) => (
                  <span key={cat} className={`badge ${CAT_BADGE[cat] ?? 'badge-info'}`}>
                    {cat} ({cnt})
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Recent alerts */}
          {[...data.as_src, ...data.as_dst]
            .sort((a, b) => b.ts - a.ts)
            .slice(0, 20)
            .map((a, i) => (
              <div
                key={i}
                className={`alert-row text-[10px] ${a.label ? 'is-attack' : 'is-normal'}`}
              >
                <span className="text-slate-600 mr-2">{a.time}</span>
                <span className="text-slate-400">{a.src} → {a.dst}</span>
                <span className="ml-2 text-slate-600">{a.proto}</span>
                <span className={`badge ml-2 ${CAT_BADGE[a.attack_type] ?? 'badge-info'}`}>
                  {a.attack_type}
                </span>
                <span className="text-slate-600 ml-2">{a.confidence.toFixed(3)}</span>
              </div>
            ))}
        </div>
      )}

      {!data && !loading && (
        <div className="flex-1 flex items-center justify-center text-slate-600 text-xs tracking-widest">
          ENTER AN IP TO INVESTIGATE
        </div>
      )}
    </div>
  )
}
