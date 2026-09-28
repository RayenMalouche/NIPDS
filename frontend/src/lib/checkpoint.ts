// Everything the checkpoint knows about the NIDS + NIPS API (src/main.py).
import { useCallback, useEffect, useRef, useState } from 'react';

export const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export interface Stats {
  total_packets: number;
  threats_detected: number;
  packets_blocked: number;
  packets_prevented: number;
  normal_traffic: number;
  detection_rate: number;
  prevention_rate: number;
  uptime_seconds: number;
  nips_active_blocks: number;
  nips_total_blocks: number;
  nips_auto_unblocks?: number;
  auto_blocking_enabled?: boolean;
}

export interface Alert {
  id: number;
  timestamp: string;
  alert_type: string;
  severity: string;
  source_ip: string;
  dest_ip: string;
  source_port?: number;
  dest_port?: number;
  protocol: string;
  description?: string;
  confidence?: number;
  blocked: boolean;
  prevention_action?: string;
}

const EMPTY_STATS: Stats = {
  total_packets: 0,
  threats_detected: 0,
  packets_blocked: 0,
  packets_prevented: 0,
  normal_traffic: 0,
  detection_rate: 0,
  prevention_rate: 0,
  uptime_seconds: 0,
  nips_active_blocks: 0,
  nips_total_blocks: 0,
};

// ---------------------------------------------------------------- lanes

/** One lane per detection rule in src/main.py, in the order the rules run. */
export const GATES = [
  { type: 'Port Scan', name: 'Port scan', rule: 'more than 20 ports from one source in 10 s' },
  { type: 'SYN Flood', name: 'SYN flood', rule: 'more than 100 SYNs from one source in 10 s' },
  { type: 'Suspicious Port Access', name: 'Suspicious port', rule: 'any packet to port 23, 135 or 139' },
  { type: 'DDoS Attempt', name: 'DDoS', rule: 'more than 100 ports from one source in 10 s' },
];

export type Tone = 'stop' | 'amber' | 'concrete';

/** What the barrier did, from the engine's `prevention_action`. */
export function verdict(alert: Alert): { label: string; tone: Tone; solid: boolean } {
  switch (alert.prevention_action) {
    case 'blocked':
      return { label: 'Turned back', tone: 'stop', solid: true };
    case 'already_blocked':
      return { label: 'Already held', tone: 'stop', solid: false };
    case 'rate_limited':
      return { label: 'Slowed', tone: 'amber', solid: true };
    case 'log':
      return { label: 'Flagged', tone: 'amber', solid: false };
    case 'error':
      return { label: 'Barrier fault', tone: 'stop', solid: false };
    default:
      return alert.blocked ? { label: 'Turned back', tone: 'stop', solid: true } : { label: 'Waved through', tone: 'concrete', solid: false };
  }
}

export const clock = (iso: string | number | Date) => new Date(iso).toLocaleTimeString('en-GB', { hour12: false });

export function duration(seconds: number) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
export const isIp = (s: string) => IPV4.test(s.trim());

// ---------------------------------------------------------------- polling

const getJson = async <T,>(path: string, signal?: AbortSignal): Promise<T> => {
  const res = await fetch(`${API_BASE}${path}`, { signal });
  if (!res.ok) throw new Error(`${path} answered ${res.status}`);
  return res.json();
};

const post = async (path: string, body?: unknown) => {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${path} answered ${res.status}`);
  return res.json();
};

/** Polls the checkpoint every `intervalMs`; also keeps packets-per-second samples. */
export function useCheckpoint(intervalMs = 2000) {
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [held, setHeld] = useState<string[]>([]);
  const [trusted, setTrusted] = useState<string[]>([]);
  const [banned, setBanned] = useState<string[]>([]);
  const [releaseAt, setReleaseAt] = useState<Record<string, string>>({});
  const [autoBlock, setAutoBlockState] = useState<boolean | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  const [rates, setRates] = useState<number[]>([]);
  const last = useRef<{ packets: number; at: number } | null>(null);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    try {
      const [s, a, ips, status] = await Promise.all([
        getJson<Stats>('/stats', signal),
        getJson<Alert[]>('/alerts?limit=50', signal),
        getJson<{ blocked_ips: string[]; whitelist: string[]; blacklist: string[] }>('/nips/blocked-ips', signal),
        getJson<{ temp_blocks?: Record<string, string> }>('/nips/status', signal).catch(() => ({ temp_blocks: {} })),
      ]);
      setStats({ ...EMPTY_STATS, ...s });
      setAlerts(a);
      setHeld(ips.blocked_ips ?? []);
      setTrusted(ips.whitelist ?? []);
      setBanned(ips.blacklist ?? []);
      setReleaseAt(status.temp_blocks ?? {});
      setOnline(true);

      const now = Date.now();
      if (last.current && now > last.current.at) {
        const perSecond = Math.max(0, (s.total_packets - last.current.packets) / ((now - last.current.at) / 1000));
        setRates((prev) => [...prev, perSecond].slice(-40));
      }
      last.current = { packets: s.total_packets, at: now };
    } catch (err) {
      if ((err as Error).name !== 'AbortError') setOnline(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    // The server is the source of truth for auto-block, not a local default.
    getJson<{ auto_block_enabled: boolean }>('/nips/config', controller.signal)
      .then((c) => setAutoBlockState(!!c.auto_block_enabled))
      .catch(() => undefined);
    refresh(controller.signal);
    const id = setInterval(() => refresh(), intervalMs);
    return () => {
      controller.abort();
      clearInterval(id);
    };
  }, [intervalMs, refresh]);

  const act = useCallback(
    async (fn: () => Promise<unknown>) => {
      await fn();
      await refresh();
    },
    [refresh],
  );

  return {
    stats,
    alerts,
    held,
    trusted,
    banned,
    releaseAt,
    autoBlock,
    online,
    rates,
    setAutoBlock: (enabled: boolean) =>
      act(async () => {
        const res = await post(`/nips/config/auto-block?enabled=${enabled}`);
        setAutoBlockState(!!res.auto_block_enabled);
      }),
    trust: (ip: string) => act(() => post('/nips/whitelist', { ip, action: 'whitelist' })),
    ban: (ip: string) => act(() => post('/nips/blacklist', { ip, action: 'blacklist' })),
    hold: (ip: string) => act(() => post('/nips/block', { ip, action: 'block' })),
    release: (ip: string) => act(() => post('/nips/unblock', { ip, action: 'unblock' })),
  };
}

export type Checkpoint = ReturnType<typeof useCheckpoint>;
