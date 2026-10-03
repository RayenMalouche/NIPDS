// The inspection log: every recent detection, newest first, with what the
// barrier did about it stamped on the right.
import { Alert, clock, GATES, verdict } from '../../lib/checkpoint';
import { cn } from '../../lib/cn';

const SEVERITY: Record<string, string> = {
  critical: 'bg-stop text-paint',
  high: 'border border-stop text-stop',
  medium: 'border border-amber text-amber',
  low: 'border border-concrete/60 text-concrete',
};

export function InspectionLog({ alerts, guarding }: { alerts: Alert[]; guarding: boolean }) {
  const gateOf = (type: string) => {
    const i = GATES.findIndex((g) => g.type === type);
    return i >= 0 ? String(i + 1) : '·';
  };

  return (
    <section aria-labelledby="log-title">
      <h2 id="log-title" className="sign-label mb-3">
        Inspection log · last {Math.min(15, alerts.length)}
      </h2>
      {alerts.length === 0 ? (
        <p className="slab px-5 py-8 text-center text-concrete">Nothing to inspect, only clear traffic so far.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] border-collapse text-sm">
            <thead>
              <tr className="sign-label text-left">
                <th className="px-3 py-2 font-bold">Time</th>
                <th className="px-3 py-2 font-bold">Gate</th>
                <th className="px-3 py-2 font-bold">From</th>
                <th className="px-3 py-2 font-bold">To</th>
                <th className="px-3 py-2 font-bold">Severity</th>
                <th className="px-3 py-2 text-right font-bold">{guarding ? 'Barrier' : 'Status'}</th>
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 15).map((a) => {
                const v = verdict(a);
                return (
                  <tr key={a.id} className="border-t border-paint/10">
                    <td className="whitespace-nowrap px-3 py-2.5 font-mono text-concrete">{clock(a.timestamp)}</td>
                    <td className="whitespace-nowrap px-3 py-2.5">
                      <span className="font-stencil text-lg text-amber">{gateOf(a.alert_type)}</span> <span>{a.alert_type}</span>
                    </td>
                    <td className="px-3 py-2.5 font-mono">{a.source_ip}</td>
                    <td className="whitespace-nowrap px-3 py-2.5 font-mono text-concrete">
                      {a.dest_ip}
                      {a.dest_port ? `:${a.dest_port}` : ''} <span className="text-[0.7rem]">{a.protocol}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={cn('px-2 py-0.5 text-[0.7rem] font-bold uppercase tracking-wider', SEVERITY[a.severity.toLowerCase()] ?? SEVERITY.low)}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      {guarding ? (
                        <span
                          className={cn(
                            'inline-block -rotate-2 border-2 px-2 py-0.5 font-stencil text-sm uppercase tracking-wider',
                            v.tone === 'stop' && (v.solid ? 'border-stop bg-stop text-paint' : 'border-stop text-stop'),
                            v.tone === 'amber' && (v.solid ? 'border-amber bg-amber text-asphalt' : 'border-amber text-amber'),
                            v.tone === 'concrete' && 'border-concrete/60 text-concrete',
                          )}
                        >
                          {v.label}
                        </span>
                      ) : (
                        <span className="font-stencil text-sm uppercase tracking-wider text-amber">Detected</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
