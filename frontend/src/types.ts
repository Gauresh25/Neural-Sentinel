export interface Alert {
  time: string
  ts: number
  src: string
  dst: string
  proto: string
  service: string
  label: number
  confidence: number
  attack_type: string
}

export interface Stats {
  total: number
  attacks: number
  normal: number
  elapsed_s: number
  attack_rate: number
  by_category: Record<string, number>
  start_time: number
}

export interface SummaryData {
  categories: Record<string, number>
  total_attacks: number
}

export interface ConfBin {
  range: string
  total: number
  attack: number
  normal: number
}

export interface ConfidenceData {
  bins: ConfBin[]
  threshold: number
}

export interface ThreatData {
  ip: string
  as_src: Alert[]
  as_dst: Alert[]
  summary: {
    total: number
    attacks: number
    as_src: number
    as_dst: number
    categories: Record<string, number>
  }
}
