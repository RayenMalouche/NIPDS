import { useState } from 'react';

import { Gantry, Mode } from './components/checkpoint/gantry';
import { GateStrip } from './components/checkpoint/gate-strip';
import { HoldingBay } from './components/checkpoint/holding-bay';
import { InspectionLog } from './components/checkpoint/inspection-log';
import { TrafficCounter } from './components/checkpoint/traffic-counter';
import { API_BASE, useCheckpoint } from './lib/checkpoint';

function App() {
  // Prevention is the point of this build, so Guard is the default — as before.
  const [mode, setMode] = useState<Mode>('guard');
  const cp = useCheckpoint();
  const packetRate = cp.rates[cp.rates.length - 1] ?? 0;
  const guarding = mode === 'guard';

  return (
    <div className="min-h-screen">
      <Gantry
        mode={mode}
        onMode={setMode}
        online={cp.online}
        autoBlock={cp.autoBlock}
        onAutoBlock={cp.setAutoBlock}
        stats={cp.stats}
        packetRate={packetRate}
      />

      <main className="mx-auto max-w-7xl space-y-10 px-4 py-8 sm:px-6">
        {cp.online === false && (
          <p role="alert" className="border-l-4 border-stop bg-tarmac px-5 py-3">
            The engine at <span className="font-mono">{API_BASE}</span> isn’t answering. Figures below are the last ones it sent.
          </p>
        )}

        <GateStrip alerts={cp.alerts} packetRate={packetRate} guarding={guarding} autoBlock={cp.autoBlock} />

        <div className="grid gap-6 lg:grid-cols-[2fr_3fr]">
          <TrafficCounter rates={cp.rates} />
          <div className="slab px-5 py-4 text-sm leading-relaxed text-concrete">
            <p className="sign-label mb-2">How to read the road</p>
            {guarding ? (
              <p>
                Each numbered lane is one detection rule. Sources the barrier <span className="text-stop">turned back</span> queue in front of it;
                ones only <span className="text-amber">flagged or slowed</span> go past. A lane’s barrier stays down for a minute after its last block.
              </p>
            ) : (
              <p>
                Observe mode shows detections only — no barrier. Every source a rule flags drives through in <span className="text-amber">amber</span>.
                Switch to Guard to see what the firewall did about them.
              </p>
            )}
          </div>
        </div>

        {guarding && (
          <HoldingBay
            held={cp.held}
            trusted={cp.trusted}
            banned={cp.banned}
            releaseAt={cp.releaseAt}
            alerts={cp.alerts}
            onRelease={cp.release}
            onTrust={cp.trust}
            onBan={cp.ban}
            onHold={cp.hold}
          />
        )}

        <InspectionLog alerts={cp.alerts} guarding={guarding} />
      </main>

      <footer className="border-t border-paint/10 py-5 text-center font-mono text-xs text-concrete">
        NIPDS · ML + rule-based detection with active prevention · API {API_BASE}
      </footer>
    </div>
  );
}

export default App;
