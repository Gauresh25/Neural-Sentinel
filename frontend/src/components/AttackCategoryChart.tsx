import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import type { SummaryData } from '../types'

interface Props {
  data: SummaryData | null
}

const CAT_COLORS: Record<string, string> = {
  'DoS':               '#ff2d55',
  'Reconnaissance':    '#ff9f0a',
  'Brute Force (SSH)': '#ff6b6b',
  'Backdoor':          '#bf5af2',
  'Worms':             '#ff375f',
  'Fuzzers':           '#ffd60a',
  'Shellcode':         '#ff453a',
  'Exploits':          '#e63946',
  'Analysis':          '#0a84ff',
  'Generic':           '#4a5568',
}

const fallback = '#64748b'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null
  const { name, value } = payload[0]
  return (
    <div className="card text-xs py-1.5 px-3">
      <span style={{ color: CAT_COLORS[name] ?? fallback }}>{name}</span>
      <span className="text-slate-300 ml-2">{value} alerts</span>
    </div>
  )
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CustomLegend = ({ payload }: any) => (
  <ul className="flex flex-wrap gap-x-3 gap-y-1 justify-center mt-2">
    {payload?.map((entry: { value: string; color: string }) => (
      <li key={entry.value} className="flex items-center gap-1 text-[10px] text-slate-400">
        <span className="inline-block w-2 h-2 rounded-full" style={{ background: entry.color }} />
        {entry.value}
      </li>
    ))}
  </ul>
)

export function AttackCategoryChart({ data }: Props) {
  const entries = Object.entries(data?.categories ?? {})
  const chartData = entries
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const hasData = chartData.length > 0

  return (
    <div className="card glow-red" style={{ minHeight: 280 }}>
      <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase mb-1">
        Attack Categories
      </div>
      <div className="text-xs text-slate-600 mb-3">
        {data?.total_attacks ?? 0} attacks detected
      </div>

      {hasData ? (
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={chartData}
              cx="50%"
              cy="50%"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {chartData.map((entry) => (
                <Cell key={entry.name} fill={CAT_COLORS[entry.name] ?? fallback} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend content={<CustomLegend />} />
          </PieChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-44 text-slate-600 text-xs tracking-widest">
          NO ATTACKS YET
        </div>
      )}
    </div>
  )
}
