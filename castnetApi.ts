/**
 * castnetApi.ts — CASTNET + Rayhunter Pi API service layer
 *
 * Tries LAN first (192.168.1.239), falls back to Tailscale (100.68.146.48).
 * All calls have a 5s timeout. Never throws — returns null on failure.
 */

import axios from 'axios';

const ENDPOINTS = [
  'http://192.168.1.239:5000',
  'http://100.68.146.48:5000',
];

const TIMEOUT = 5000;

// ── Find a working endpoint ────────────────────────────────────────── //
let _activeEndpoint: string | null = null;

async function getEndpoint(): Promise<string | null> {
  if (_activeEndpoint) return _activeEndpoint;
  for (const ep of ENDPOINTS) {
    try {
      await axios.get(`${ep}/api/v1/summary`, { timeout: 2000 });
      _activeEndpoint = ep;
      return ep;
    } catch {
      continue;
    }
  }
  return null;
}

// Reset so next call re-probes (call when network changes)
export function resetEndpoint() {
  _activeEndpoint = null;
}

// ── Types ──────────────────────────────────────────────────────────── //
export interface CastnetNode {
  node_id: string;
  last_seen: string;
  rogue_hits: number;
  total_scans: number;
  tier: number;
}

export interface LastRogueDetection {
  ci: number;
  node_id: string;
  rsrp: number;
  timestamp: string;
}

export interface CastnetSummary {
  castnet: string;
  active_nodes: number;
  total_events: number;
  rogue_detections: number;
  known_rogue_cid_count: number;
  unique_rogue_cids: number;
  nodes: CastnetNode[];
  last_rogue_detection: LastRogueDetection;
}

export interface CastnetDetection {
  id: number;
  timestamp: string;
  node_id: string;
  ci: number;
  tac: number;
  mcc: number;
  mnc: number;
  rsrp: number;
  rssi: number;
  timing_advance: number;
  bands: string;
  latitude: number | null;
  longitude: number | null;
  confirmed_rogue: number;
  watchlist: number;
}

export interface CorroborationEntry {
  cid: number;
  level: string;
  n_sources: number;
  has_rf: boolean;
  has_firmware: boolean;
  has_castnet: boolean;
  rf_count: number;
  firmware_count: number;
  castnet_count: number;
  device_note: string;
}

export interface RayhunterFinding {
  detector: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  evidence: string[];
  corroboration?: CorroborationEntry;
}

export interface RayhunterReport {
  threat_level: string;
  findings: RayhunterFinding[];
  yaicd_score: number;
  yaicd_verdict: string;
  confirmed_heuristics: number;
  events_analyzed: number;
  generated_at: string;
}

// ── API calls ──────────────────────────────────────────────────────── //

export async function fetchSummary(): Promise<CastnetSummary | null> {
  const ep = await getEndpoint();
  if (!ep) return null;
  try {
    const r = await axios.get(`${ep}/api/v1/summary`, { timeout: TIMEOUT });
    return r.data as CastnetSummary;
  } catch {
    return null;
  }
}

export async function fetchRecentDetections(
  limit = 50,
): Promise<CastnetDetection[]> {
  const ep = await getEndpoint();
  if (!ep) return [];
  try {
    const r = await axios.get(`${ep}/api/v1/detections?limit=${limit}`, {
      timeout: TIMEOUT,
    });
    return r.data as CastnetDetection[];
  } catch {
    return [];
  }
}

export async function fetchRogueDetections(
  limit = 200,
): Promise<CastnetDetection[]> {
  const dets = await fetchRecentDetections(limit);
  return dets.filter(d => d.confirmed_rogue === 1);
}

export async function fetchLatestReport(): Promise<RayhunterReport | null> {
  const ep = await getEndpoint();
  if (!ep) return null;
  try {
    const r = await axios.get(`${ep}/api/v1/latest_report`, {
      timeout: TIMEOUT,
    });
    return r.data as RayhunterReport;
  } catch {
    return null;
  }
}

export async function pingApi(): Promise<boolean> {
  const ep = await getEndpoint();
  return ep !== null;
}
