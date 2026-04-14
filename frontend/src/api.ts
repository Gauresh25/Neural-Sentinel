const BASE = '/api'

const get = (path: string) => fetch(`${BASE}${path}`).then(r => r.json())

export const fetchStats           = () => get('/stats')
export const fetchSummary         = () => get('/summary')
export const fetchConfidenceDist  = () => get('/confidence-distribution')
export const fetchThreshold       = () => get('/threshold')
export const fetchThreat          = (ip: string) => get(`/threat/${encodeURIComponent(ip)}`)

export const postThreshold = (threshold: number) =>
  fetch(`${BASE}/threshold`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ threshold }),
  }).then(r => r.json())
