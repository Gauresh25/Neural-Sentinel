import type { Alert } from '../types'

interface Props {
  alerts: Alert[]
}

const CAT_BADGE: Record<string, string> = {
  'DoS':               'badge-attack',
  'Reconnaissance':    'badge-warn',
  'Brute Force (SSH)': 'badge-attack',
  'Backdoor':          'badge-purple',
  'Worms':             'badge-attack',
  'Fuzzers':           'badge-warn',
  'Shellcode':         'badge-attack',
  'Exploits':          'badge-attack',
  'Analysis':          'badge-info',
  'Generic':           'badge-info',
  'Normal':            'badge-normal',
}

function ConfBar({ value }: { value: number }) {
  const isAttack = value >= 0.5
  const color = isAttack ? '#ff2d55' : '#00ff88'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1 rounded-full bg-[#1c2333] overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${value * 100}%`, background: color }}
        />
      </div>
      <span style={{ color, fontSize: 10 }}>{value.toFixed(3)}</span>
    </div>
  )
}

export function AlertFeed({ alerts }: Props) {
  return (
    <div className="card flex flex-col" style={{ minHeight: 340 }}>
      <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase mb-1 shrink-0">
        Live Alert Feed
      </div>
      <div className="text-xs text-slate-600 mb-3 flex items-center justify-between shrink-0">
        <span>{alerts.length} in buffer</span>
        <span className="flex items-center gap-1">
          <span className="pulse-dot inline-block w-1.5 h-1.5 rounded-full bg-[#00ff88]" />
          streaming
        </span>
      </div>

      <div className="overflow-y-auto flex-1 space-y-1 pr-1" style={{ maxHeight: 280 }}>
        {alerts.length === 0 && (
          <div className="text-slate-600 text-xs text-center pt-16 tracking-widest">
            WAITING FOR TRAFFIC…
          </div>
        )}
        {alerts.map((a, i) => (
          <div
            key={`${a.ts}-${i}`}
            className={`alert-row ${a.label ? 'is-attack' : 'is-normal'}`}
          >
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-slate-600 shrink-0 w-16">{a.time}</span>
              <span className="text-slate-300 font-medium truncate max-w-[90px]" title={a.src}>
                {a.src}
              </span>
              <span className="text-slate-600">→</span>
              <span className="text-slate-300 font-medium truncate max-w-[90px]" title={a.dst}>
                {a.dst}
              </span>
              <span className="text-slate-600 shrink-0">{a.proto}/{a.service}</span>
              <span className={`badge ${CAT_BADGE[a.attack_type] ?? 'badge-info'} shrink-0`}>
                {a.attack_type}
              </span>
              <div className="ml-auto shrink-0">
                <ConfBar value={a.confidence} />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
