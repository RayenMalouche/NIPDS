// The overhead sign gantry: the checkpoint's name, which mode it runs in
// (Observe = detection only, Guard = detection + prevention), the barrier
// control, and the counters a traffic authority would post above the road.
import { cn } from '../../lib/cn';
import { duration, Stats } from '../../lib/checkpoint';

export type Mode = 'observe' | 'guard';

interface GantryProps {
  mode: Mode;
  onMode: (mode: Mode) => void;
  online: boolean | null;
  autoBlock: boolean | null;
  onAutoBlock: (enabled: boolean) => void;
  stats: Stats;
  packetRate: number;
}

export function Gantry({ mode, onMode, online, autoBlock, onAutoBlock, stats, packetRate }: GantryProps) {
  const counters =
    mode === 'guard'
      ? [
          { label: 'Packets', value: stats.total_packets.toLocaleString('en') },
          { label: 'Threats', value: stats.threats_detected.toLocaleString('en'), tone: 'amber' },
          { label: 'Turned back', value: stats.packets_prevented.toLocaleString('en'), note: `${stats.prevention_rate}% of threats`, tone: 'stop' },
          { label: 'Held now', value: String(stats.nips_active_blocks), tone: 'stop' },
          { label: 'Holds so far', value: String(stats.nips_total_blocks) },
        ]
      : [
          { label: 'Packets', value: stats.total_packets.toLocaleString('en'), note: `${packetRate.toFixed(0)} a second` },
          { label: 'Threats', value: stats.threats_detected.toLocaleString('en'), note: `${stats.detection_rate}% of traffic`, tone: 'amber' },
          { label: 'Clear traffic', value: stats.normal_traffic.toLocaleString('en'), tone: 'pass' },
          { label: 'On watch', value: duration(stats.uptime_seconds) },
        ];

  return (
    <header className="border-b-4 border-amber">
      <div className="mx-auto max-w-7xl px-4 pb-6 pt-7 sm:px-6">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <div>
            <p className="sign-label flex items-center gap-2">
              <span
                className={cn('h-2.5 w-2.5 rounded-full', online === null ? 'bg-concrete' : online ? 'bg-pass' : 'bg-stop')}
                aria-hidden
              />
              {online === null ? 'Contacting the engine…' : online ? 'Engine reporting' : 'Engine not answering'}
            </p>
            <h1 className="mt-2 font-stencil text-5xl leading-none sm:text-6xl">
              NIPDS <span className="text-amber">checkpoint</span>
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Mode: lane-control sign */}
            <div role="radiogroup" aria-label="Mode" className="flex border-2 border-paint/30">
              {(
                [
                  ['observe', 'Observe', 'detection only'],
                  ['guard', 'Guard', 'detect + prevent'],
                ] as const
              ).map(([value, label, hint]) => (
                <button
                  key={value}
                  role="radio"
                  aria-checked={mode === value}
                  onClick={() => onMode(value)}
                  className={cn('px-4 py-2 text-left transition-colors', mode === value ? 'bg-paint text-asphalt' : 'text-paint hover:bg-paint/10')}
                >
                  <span className="block font-extrabold uppercase tracking-wide">{label}</span>
                  <span className="block text-[0.7rem] opacity-70">{hint}</span>
                </button>
              ))}
            </div>

            {mode === 'guard' && (
              <button
                type="button"
                role="switch"
                aria-checked={!!autoBlock}
                disabled={autoBlock === null}
                onClick={() => onAutoBlock(!autoBlock)}
                className={cn(
                  'flex items-center gap-3 border-2 px-4 py-2 text-left transition-colors',
                  autoBlock ? 'border-stop' : 'border-paint/30 hover:border-paint',
                )}
              >
                <span className={cn('h-8 w-2', autoBlock ? 'boom' : 'bg-concrete/50')} aria-hidden />
                <span>
                  <span className="block font-extrabold uppercase tracking-wide">
                    Barrier {autoBlock === null ? '…' : autoBlock ? 'automatic' : 'open'}
                  </span>
                  <span className="block text-[0.7rem] opacity-70">{autoBlock ? 'threats are blocked' : 'threats are only logged'}</span>
                </span>
              </button>
            )}
          </div>
        </div>

        <dl className={cn('mt-7 grid grid-cols-2 gap-px bg-paint/10 sm:grid-cols-3', counters.length === 5 ? 'lg:grid-cols-5' : 'sm:grid-cols-4')}>
          {counters.map((c, i) => (
            <div
              key={c.label}
              className={cn('bg-asphalt px-4 py-3', counters.length % 2 === 1 && i === counters.length - 1 && 'col-span-2 sm:col-span-1')}
            >
              <dt className="sign-label">{c.label}</dt>
              <dd
                className={cn(
                  'mt-1 font-mono text-3xl font-semibold tabular-nums',
                  c.tone === 'stop' && 'text-stop',
                  c.tone === 'amber' && 'text-amber',
                  c.tone === 'pass' && 'text-pass',
                )}
              >
                {c.value}
              </dd>
              {c.note && <dd className="text-xs text-concrete">{c.note}</dd>}
            </div>
          ))}
        </dl>
      </div>
    </header>
  );
}
