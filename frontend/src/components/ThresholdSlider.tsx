import { useEffect, useRef, useState } from 'react'
import { postThreshold } from '../api'

interface Props {
  threshold: number
  onChange: (v: number) => void
}

export function ThresholdSlider({ threshold, onChange }: Props) {
  const [local, setLocal] = useState(threshold)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => { setLocal(threshold) }, [threshold])

  const handle = (v: number) => {
    setLocal(v)
    onChange(v)
    setSaved(false)
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(async () => {
      setSaving(true)
      try {
        await postThreshold(v)
        setSaved(true)
      } finally {
        setSaving(false)
        setTimeout(() => setSaved(false), 1500)
      }
    }, 400)
  }

  const fpRate = local < 0.5 ? 'HIGH' : local < 0.7 ? 'MED' : 'LOW'
  const fnRate = local > 0.7 ? 'HIGH' : local > 0.5 ? 'MED' : 'LOW'
  const fpColor = fpRate === 'HIGH' ? '#ff2d55' : fpRate === 'MED' ? '#ffd60a' : '#00ff88'
  const fnColor = fnRate === 'HIGH' ? '#ff2d55' : fnRate === 'MED' ? '#ffd60a' : '#00ff88'

  return (
    <div className="card" style={{ padding: '0.75rem 1rem' }}>
      <div className="flex items-center gap-4">
        <div className="text-[9px] text-slate-500 tracking-[0.18em] uppercase shrink-0">
          Classifier Threshold
        </div>

        <div className="flex-1 flex items-center gap-3">
          <span className="text-[10px] text-slate-600">0.0</span>
          <input
            type="range"
            min={0.01}
            max={0.99}
            step={0.01}
            value={local}
            onChange={e => handle(parseFloat(e.target.value))}
            className="flex-1 accent-[#ffd60a] cursor-pointer"
            style={{ accentColor: '#ffd60a' }}
          />
          <span className="text-[10px] text-slate-600">1.0</span>
        </div>

        <div className="text-lg font-bold text-[#ffd60a] w-12 text-center shrink-0">
          {local.toFixed(2)}
        </div>

        <div className="flex gap-3 text-[9px] shrink-0">
          <span>
            FP <span style={{ color: fpColor }} className="font-bold">{fpRate}</span>
          </span>
          <span>
            FN <span style={{ color: fnColor }} className="font-bold">{fnRate}</span>
          </span>
        </div>

        <div className="w-12 text-[9px] text-right shrink-0">
          {saving && <span className="text-slate-500">saving…</span>}
          {saved  && <span className="text-[#00ff88]">saved ✓</span>}
        </div>
      </div>
    </div>
  )
}
