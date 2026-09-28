// The signature element: the checkpoint seen from above. The clear lane carries
// ordinary traffic (its surface shimmers with the live packet rate); below it,
// one lane per detection rule. Sources the barrier turned back queue up in
// front of it; flagged ones pass it. In Observe mode there is no barrier — the
// checkpoint only watches.
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';

import { FlickeringGrid } from '../ui/flickering-grid';
import { Alert, clock, GATES, verdict } from '../../lib/checkpoint';
import { cn } from '../../lib/cn';

const MotionDiv = motion.div;
const RECENT_MS = 60_000;

interface GateStripProps {
  alerts: Alert[];
  packetRate: number;
  guarding: boolean;
  autoBlock: boolean | null;
}

export function GateStrip({ alerts, packetRate, guarding, autoBlock }: GateStripProps) {
  const known = new Set(GATES.map((g) => g.type));
  const extra = Array.from(new Set(alerts.map((a) => a.alert_type).filter((t) => !known.has(t)))).map((type) => ({
    type,
    name: type,
    rule: 'reported by the engine',
  }));
  const gates = [...GATES, ...extra];

  return (
    <section aria-labelledby="gates-title" className="bg-tarmac">
      <h2 id="gates-title" className="sr-only">
        Checkpoint lanes
      </h2>
      <ClearLane rate={packetRate} />
      {gates.map((gate, i) => (
        <Lane
          key={gate.type}
          number={i + 1}
          gate={gate}
          alerts={alerts.filter((a) => a.alert_type === gate.type)}
          guarding={guarding}
          autoBlock={autoBlock}
        />
      ))}
    </section>
  );
}

function LaneSign({ number, name, rule, tone = 'paint' }: { number: string; name: string; rule: string; tone?: 'paint' | 'pass' }) {
  return (
    <div className="flex w-full items-center gap-3 border-b border-paint/10 px-4 py-3 sm:w-56 sm:shrink-0 sm:border-b-0 sm:border-r">
      <span className={cn('font-stencil text-4xl leading-none', tone === 'pass' ? 'text-pass' : 'text-amber')}>{number}</span>
      <span className="min-w-0">
        <span className="block font-sign font-extrabold uppercase tracking-wide">{name}</span>
        <span className="block text-xs leading-snug text-concrete">{rule}</span>
      </span>
    </div>
  );
}

function ClearLane({ rate }: { rate: number }) {
  const reduceMotion = useReducedMotion();
  // Busier road, faster flicker and shorter headway between vehicles.
  const flicker = Math.min(3, 0.05 + rate / 40);
  const cars = Math.max(1, Math.min(7, Math.round(rate / 15)));
  const speed = Math.max(2.5, 9 - rate / 12);

  return (
    <div className="flex flex-col border-b-2 border-paint/15 sm:flex-row">
      <LaneSign number="0" name="Clear traffic" rule={`${rate.toFixed(0)} packets a second`} tone="pass" />
      <div className="relative h-16 flex-1 overflow-hidden bg-asphalt">
        <FlickeringGrid className="absolute inset-0" color="#3DAE6B" squareSize={3} gridGap={5} maxOpacity={0.35} flickerChance={flicker} />
        <div className="lane-mark absolute inset-x-0 top-1/2 h-0.5 -translate-y-1/2" />
        {!reduceMotion &&
          rate > 0 &&
          Array.from({ length: cars }, (_, i) => (
            <span
              key={i}
              className="absolute top-1/2 h-2 w-6 -translate-y-1/2 bg-paint/80"
              style={{ animation: `drive ${speed}s linear ${(-speed * i) / cars}s infinite` }}
              aria-hidden
            />
          ))}
      </div>
    </div>
  );
}

function Lane({ number, gate, alerts, guarding, autoBlock }: { number: number; gate: { type: string; name: string; rule: string }; alerts: Alert[]; guarding: boolean; autoBlock: boolean | null }) {
  const reduceMotion = useReducedMotion();
  const now = Date.now();
  const turnedBack = alerts.filter((a) => verdict(a).tone === 'stop');
  const passed = alerts.filter((a) => verdict(a).tone !== 'stop');
  const barrierDown = guarding && turnedBack.some((a) => now - new Date(a.timestamp).getTime() < RECENT_MS);
  // One chip per source: repeat offenders are already in the queue.
  const queue = guarding ? turnedBack.filter((a, i) => turnedBack.findIndex((b) => b.source_ip === a.source_ip) === i).slice(0, 4) : [];
  const beyond = (guarding ? passed : alerts).slice(0, 3);

  return (
    <div className="flex flex-col border-b border-paint/10 last:border-b-0 sm:flex-row">
      <LaneSign number={String(number)} name={gate.name} rule={gate.rule} />
      <div className="relative flex min-h-[4.5rem] flex-1 items-center overflow-hidden bg-asphalt">
        <div className="lane-mark absolute inset-x-0 top-1/2 h-0.5 -translate-y-1/2" aria-hidden />

        {/* Queue in front of the barrier: newest closest to it */}
        <div className="relative z-10 flex w-[62%] justify-end gap-1.5 pr-3">
          <AnimatePresence initial={false}>
            {queue
              .slice()
              .reverse()
              .map((a) => (
                <MotionDiv
                  key={a.id}
                  layout
                  initial={reduceMotion ? false : { x: -300, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ type: 'spring', stiffness: 120, damping: 20 }}
                  className="truncate bg-stop px-2 py-1 font-mono text-[0.7rem] font-semibold text-paint"
                  title={`${a.source_ip} · ${clock(a.timestamp)} · turned back`}
                >
                  {a.source_ip}
                </MotionDiv>
              ))}
          </AnimatePresence>
        </div>

        {/* The barrier */}
        <div className="relative z-20 flex h-full w-8 shrink-0 items-center justify-center" aria-hidden>
          {guarding ? (
            <>
              {/* Seen from above: lowered, the boom spans the lane; raised, it lies along the kerb. */}
              <span className="absolute top-1 h-2.5 w-2.5 bg-paint" />
              <span
                className={cn(
                  'boom absolute left-1/2 top-2 w-2 origin-top -translate-x-1/2 transition-all duration-700',
                  barrierDown ? 'h-[calc(100%-0.75rem)] opacity-100' : 'h-3 opacity-50',
                )}
              />
            </>
          ) : (
            <span className="h-3 w-3 rotate-45 border-2 border-amber" />
          )}
        </div>

        {/* Past the barrier */}
        <div className="relative z-10 flex flex-1 gap-1.5 overflow-hidden pl-3">
          {beyond.map((a, i) => {
            const v = verdict(a);
            // Older ones fade down the road. The chip stays opaque so the lane line doesn't show through it.
            const tone = {
              amber: ['border-amber text-amber', 'border-amber/60 text-amber/60', 'border-amber/35 text-amber/35'],
              stop: ['border-stop text-stop', 'border-stop/60 text-stop/60', 'border-stop/35 text-stop/35'],
              concrete: ['border-concrete/60 text-concrete', 'border-concrete/40 text-concrete/60', 'border-concrete/25 text-concrete/35'],
            }[v.tone][Math.min(i, 2)];
            return (
              <span
                key={a.id}
                className={cn('truncate border bg-asphalt px-2 py-1 font-mono text-[0.7rem]', tone)}
                title={`${a.source_ip} · ${clock(a.timestamp)} · ${v.label.toLowerCase()}`}
              >
                {a.source_ip}
              </span>
            );
          })}
        </div>

        <span className="sr-only">
          {gate.name}: {alerts.length} recent detections
          {guarding ? `, ${turnedBack.length} turned back, barrier ${barrierDown ? 'down' : 'up'}` : ''}
          {guarding && autoBlock === false ? ' (automatic blocking is off)' : ''}.
        </span>
        <span className="absolute bottom-1 right-2 z-20 font-mono text-[0.65rem] text-concrete" aria-hidden>
          {alerts.length ? `${alerts.length} seen${guarding ? ` · ${turnedBack.length} back` : ''}` : 'quiet'}
        </span>
      </div>
    </div>
  );
}
