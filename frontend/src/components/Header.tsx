import type { Stats } from '../types'

interface Props {
  stats: Stats | null
}

function fmt(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}

export function Header({ stats }: Props) {
  return (
    <header className="flex items-center justify-between px-1 py-2">
      {/* Left: brand */}
      <div className="flex items-center gap-3">
        <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
          <polygon
            points="14,2 26,8 26,20 14,26 2,20 2,8"
            stroke="#00ff88"
            strokeWidth="1.5"
            fill="rgba(0,255,136,0.06)"
          />
          <polygon
            points="14,7 21,11 21,17 14,21 7,17 7,11"
            stroke="#00ff88"
            strokeWidth="1"
            fill="rgba(0,255,136,0.04)"
          />
          <circle cx="14" cy="14" r="2.5" fill="#00ff88" />
        </svg>
        <div>
          <h1 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
            Neural Sentinel
          </h1>
          <p className="text-[10px] text-slate-500 tracking-widest">
            Bi‑LSTM Network IDS
          </p>
        </div>
      </div>

      {/* Right: status pills */}
      <div className="flex items-center gap-4 text-[11px]">
        <div className="flex items-center gap-1.5">
          <span className="pulse-dot inline-block w-2 h-2 rounded-full bg-[#00ff88]" />
          <span className="text-[#00ff88] font-semibold tracking-wider">LIVE</span>
        </div>

        {stats && (
          <>
            <div className="text-slate-500">
              uptime <span className="text-slate-300">{fmt(stats.elapsed_s)}</span>
            </div>
            <div className="text-slate-500">
              flows <span className="text-slate-300">{stats.total.toLocaleString()}</span>
            </div>
          </>
        )}
      </div>
    </header>
  )
}
