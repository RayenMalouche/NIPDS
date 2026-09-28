// A roadside traffic counter: packets per second at each poll, newest on the
// right. Replaces the old cumulative line chart, which only ever went up.
export function TrafficCounter({ rates }: { rates: number[] }) {
  const max = Math.max(1, ...rates);
  const current = rates[rates.length - 1] ?? 0;
  const slots = 40;
  const padded = [...Array(Math.max(0, slots - rates.length)).fill(null), ...rates];

  return (
    <section aria-labelledby="counter-title" className="slab px-5 py-4">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="counter-title" className="sign-label">
          Traffic counter
        </h2>
        <p className="font-mono text-2xl font-semibold tabular-nums">
          {current.toFixed(0)} <span className="text-sm text-concrete">pkt/s</span>
        </p>
      </div>
      <div className="mt-3 flex h-20 items-end gap-[3px]" role="img" aria-label={`Packets per second over the last ${rates.length} readings, now ${current.toFixed(0)}`}>
        {padded.map((r, i) => (
          <span
            key={i}
            className={i === padded.length - 1 ? 'flex-1 bg-amber' : 'flex-1 bg-paint/40'}
            style={{ height: r === null ? 2 : `${Math.max(3, (r / max) * 100)}%`, opacity: r === null ? 0.2 : 1 }}
          />
        ))}
      </div>
      <p className="mt-2 flex justify-between font-mono text-[0.65rem] text-concrete">
        <span>{Math.round((slots * 2) / 60)} min ago</span>
        <span>peak {max.toFixed(0)}</span>
        <span>now</span>
      </p>
    </section>
  );
}
