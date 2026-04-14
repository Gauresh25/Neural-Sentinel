import { useEffect, useRef, useState } from 'react'
import type { Alert } from '../types'

export function useSSE(maxItems = 200): Alert[] {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const es = new EventSource('/api/alerts')
    esRef.current = es

    es.onmessage = (e: MessageEvent) => {
      const alert: Alert = JSON.parse(e.data)
      setAlerts(prev => [alert, ...prev].slice(0, maxItems))
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [maxItems])

  return alerts
}
