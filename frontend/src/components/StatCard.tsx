interface Props {
  label: string
  value: number | string
  unit?: string
  sub?: string
  variant?: 'attack' | 'normal' | 'warn' | 'default'
}

const variantStyles: Record<string, { val: string; glow: string; accent: string }> = {
  attack:  { val: 'text-[#ff2d55]', glow: 'glow-red',   accent: 'bg-[#ff2d55]' },
  normal:  { val: 'text-[#00ff88]', glow: 'glow-green',  accent: 'bg-[#00ff88]' },
  warn:    { val: 'text-[#ffd60a]', glow: '',             accent: 'bg-[#ffd60a]' },
  default: { val: 'text-white',     glow: '',             accent: 'bg-[#0a84ff]' },
}

export function StatCard({ label, value, unit, sub, variant = 'default' }: Props) {
  const s = variantStyles[variant]
  return (
    <div className={`card ${s.glow} relative overflow-hidden`}>
      <div className={`absolute top-0 left-0 w-full h-[2px] ${s.accent} opacity-60`} />
      <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase mb-2">{label}</div>
      <div className={`text-3xl font-bold ${s.val}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
        {unit && <span className="text-xs text-slate-500 ml-1.5 font-normal">{unit}</span>}
      </div>
      {sub && <div className="text-[10px] text-slate-600 mt-1">{sub}</div>}
    </div>
  )
}
