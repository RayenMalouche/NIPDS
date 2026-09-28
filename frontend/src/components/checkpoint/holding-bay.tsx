// Guard mode only. The holding bay: every source the firewall is holding, as a
// passport with its release time. And the pass office: trust, ban or hold a
// source by hand.
import { FormEvent, useState } from 'react';

import { EvervaultCard } from '../ui/evervault-card';
import { Alert, clock, isIp } from '../../lib/checkpoint';
import { cn } from '../../lib/cn';

interface HoldingBayProps {
  held: string[];
  trusted: string[];
  banned: string[];
  releaseAt: Record<string, string>;
  alerts: Alert[];
  onRelease: (ip: string) => Promise<void>;
  onTrust: (ip: string) => Promise<void>;
  onBan: (ip: string) => Promise<void>;
  onHold: (ip: string) => Promise<void>;
}

export function HoldingBay({ held, trusted, banned, releaseAt, alerts, onRelease, onTrust, onBan, onHold }: HoldingBayProps) {
  const [ip, setIp] = useState('');
  const [message, setMessage] = useState<{ text: string; tone: 'pass' | 'stop' } | null>(null);
  const [busy, setBusy] = useState(false);
  const valid = isIp(ip);

  const run = async (action: (ip: string) => Promise<void>, done: string) => {
    if (!valid) return;
    setBusy(true);
    try {
      await action(ip.trim());
      setMessage({ text: `${ip.trim()} ${done}`, tone: 'pass' });
      setIp('');
    } catch (err) {
      setMessage({ text: (err as Error).message, tone: 'stop' });
    } finally {
      setBusy(false);
    }
  };

  const lastSeen = (source: string) => alerts.find((a) => a.source_ip === source);

  return (
    <div className="grid gap-6 lg:grid-cols-[3fr_2fr]">
      <section aria-labelledby="bay-title">
        <h2 id="bay-title" className="sign-label mb-3">
          Holding bay · {held.length}
        </h2>
        {held.length === 0 ? (
          <p className="slab px-5 py-8 text-center text-concrete">No one is being held. The barrier lowers here when it turns a source back.</p>
        ) : (
          <ul className="grid gap-3 sm:grid-cols-2">
            {held.map((source) => {
              const seen = lastSeen(source);
              const until = releaseAt[source];
              return (
                <li key={source}>
                  <EvervaultCard className="border-l-4 border-stop bg-tarmac">
                    <div className="px-4 py-3">
                      <p className="sign-label !text-stop">Held</p>
                      <p className="mt-1 font-mono text-xl font-semibold">{source}</p>
                      <p className="mt-1 text-sm text-concrete">
                        {seen ? `${seen.alert_type} at ${clock(seen.timestamp)}` : 'Held by hand or from an earlier session'}
                      </p>
                      <div className="mt-3 flex items-center justify-between gap-3">
                        <span className="font-mono text-xs text-concrete">{until ? `release ${clock(until)}` : 'until released'}</span>
                        <button type="button" onClick={() => onRelease(source)} className="btn border border-paint/40 px-3 py-1 text-xs hover:border-paint">
                          Release
                        </button>
                      </div>
                    </div>
                  </EvervaultCard>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section aria-labelledby="office-title" className="space-y-5">
        <h2 id="office-title" className="sign-label">
          Pass office
        </h2>
        <form onSubmit={(e: FormEvent) => e.preventDefault()} className="slab space-y-3 px-5 py-4">
          <label htmlFor="ip" className="block text-sm">
            Source address
          </label>
          <input
            id="ip"
            value={ip}
            onChange={(e) => {
              setIp(e.target.value);
              setMessage(null);
            }}
            placeholder="203.0.113.7"
            inputMode="decimal"
            aria-invalid={ip !== '' && !valid}
            className={cn(
              'w-full border-2 bg-asphalt px-3 py-2 font-mono text-lg text-paint placeholder:text-concrete/50 focus:outline-none',
              ip && !valid ? 'border-amber' : 'border-paint/20 focus:border-paint',
            )}
          />
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={!valid || busy} onClick={() => run(onTrust, 'is a trusted traveller')} className="btn bg-pass text-asphalt hover:bg-pass/85">
              Trust
            </button>
            <button type="button" disabled={!valid || busy} onClick={() => run(onBan, 'is banned')} className="btn bg-stop text-paint hover:bg-stop/85">
              Ban
            </button>
            <button type="button" disabled={!valid || busy} onClick={() => run(onHold, 'is held for an hour')} className="btn border border-paint/40 hover:border-paint">
              Hold 1 h
            </button>
          </div>
          {ip && !valid && <p className="text-sm text-amber">That isn’t an IPv4 address.</p>}
          {message && (
            <p role="status" className={cn('text-sm', message.tone === 'pass' ? 'text-pass' : 'text-stop')}>
              {message.text}
            </p>
          )}
        </form>

        <IpList title="Trusted travellers" tone="pass" ips={trusted} empty="Nobody is on the trusted list." />
        <IpList title="Banned" tone="stop" ips={banned} empty="Nobody is banned." />
      </section>
    </div>
  );
}

function IpList({ title, tone, ips, empty }: { title: string; tone: 'pass' | 'stop'; ips: string[]; empty: string }) {
  return (
    <div>
      <h3 className="sign-label mb-2">
        {title} · {ips.length}
      </h3>
      {ips.length === 0 ? (
        <p className="text-sm text-concrete">{empty}</p>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {ips.map((ip) => (
            <li key={ip} className={cn('border px-2 py-1 font-mono text-sm', tone === 'pass' ? 'border-pass text-pass' : 'border-stop text-stop')}>
              {ip}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
