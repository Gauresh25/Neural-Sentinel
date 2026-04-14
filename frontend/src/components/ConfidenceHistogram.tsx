import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ReferenceLine,
  ResponsiveContainer, Cell,
} from 'recharts'
import type { ConfidenceData } from '../types'

interface Props {
  data: ConfidenceData | null
  threshold: number
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  const bin = payload[0]?.payload
  return (
    <div className="card text-xs py-1.5 px-3 space-y-0.5">
      <div className="text-slate-400">{label}</div>
      <div className="text-[#00ff88]">normal: {bin?.normal ?? 0}</div>
      <div className="text-[#ff2d55]">attack: {bin?.attack ?? 0}</div>
    </div>
  )
}

export function ConfidenceHistogram({ data, threshold }: Props) {
  const bins = data?.bins ?? []
  const total = bins.reduce((s, b) => s + b.total, 0)

  return (
    <div className="card glow-blue" style={{ minHeight: 280 }}>
      <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase mb-1">
        Confidence Distribution
      </div>
      <div className="text-xs text-slate-600 mb-3 flex items-center justify-between">
        <span>{total} samples</span>
        <span>
          threshold{' '}
          <span className="text-[#ffd60a] font-semibold">{threshold.toFixed(2)}</span>
        </span>
      </div>

      {total > 0 ? (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={bins} barSize={18} margin={{ left: -20, right: 8, bottom: 0 }}>
            <XAxis
              dataKey="range"
              tick={{ fontSize: 9, fill: '#475569', fontFamily: 'JetBrains Mono' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 9, fill: '#475569', fontFamily: 'JetBrains Mono' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            {/* Threshold reference */}
            <ReferenceLine
              x={bins.find(b => {
                const lo = parseFloat(b.range.split('–')[0])
                return lo <= threshold && threshold < lo + 0.1
              })?.range}
              stroke="#ffd60a"
              strokeDasharray="4 3"
              strokeWidth={1.5}
              label={{
                value: `τ=${threshold.toFixed(2)}`,
                position: 'insideTopRight',
                fontSize: 9,
                fill: '#ffd60a',
              }}
            />
            <Bar dataKey="total" radius={[3, 3, 0, 0]}>
              {bins.map((bin) => {
                const lo = parseFloat(bin.range.split('–')[0])
                return (
                  <Cell
                    key={bin.range}
                    fill={lo >= threshold ? 'rgba(255,45,85,0.75)' : 'rgba(10,132,255,0.55)'}
                  />
                )
              })}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-44 text-slate-600 text-xs tracking-widest">
          AWAITING DATA
        </div>
      )}
    </div>
  )
}
