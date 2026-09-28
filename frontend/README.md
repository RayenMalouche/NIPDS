# NIPDS — the checkpoint

The frontend for the NIDS + NIPS engine (`src/main.py`). React 19 + TypeScript on
Create React App, Tailwind v3 and framer-motion. It polls the engine every two
seconds.

```bash
npm install
npm start          # http://localhost:3000 — expects the engine at http://localhost:8000
npm run build      # production build → build/, served by nginx in the Dockerfile
```

Point it at another engine with `REACT_APP_API_URL=http://host:8000` at build time.

## The design

The page is **a border checkpoint on a road at night**. That's what an intrusion
*prevention* system is: traffic arrives, most of it drives through, some gets
inspected, and some is turned back at a barrier. Every device on the page comes
from that crossing:

- **The lanes** (`components/checkpoint/gate-strip.tsx`) are the signature element.
  Lane 0 carries clear traffic. Its surface shimmers, and its vehicles move
  faster, with the live packet rate. Lanes 1–4 are the engine's four detection
  rules (port scan, SYN flood, suspicious port, DDoS), each with its threshold on
  the lane sign.
  - Sources the barrier **turned back** queue in front of a red-and-white boom.
    Those only **flagged or slowed** drive past it.
  - A lane's boom stays down for a minute after its last block.
- **Observe and Guard** replace the two separate dashboards the app used to switch
  between. They show the same road; Observe (detection only) just has no barrier.
- **The barrier control**: the auto-block switch, now read from `GET /nips/config`
  on load instead of assuming "on".
- **The holding bay**: every source the firewall is holding, as a passport with
  what it did and when it will be released (from `/nips/status` → `temp_blocks`).
  Hover a passport and its bytes show through.
- **The pass office**: trust, ban or hold (one hour) a source by hand, with IPv4
  validation. *Hold* uses `POST /nips/block`, which the old UI never exposed.
- **The traffic counter**: packets per second at each poll. The old line chart
  plotted cumulative totals, which only ever went up.
- **The inspection log**: every recent detection, with the barrier's verdict
  stamped on it: *turned back*, *already held*, *slowed*, *flagged* or *waved
  through*, from the engine's `prevention_action`.

**Palette**: defined once in `tailwind.config.js`. Each colour has one job:

| Token | Hex | Role |
| --- | --- | --- |
| `asphalt` | `#1C1F23` | page ground, the road at night |
| `tarmac` | `#262A30` | panels, lane signs |
| `paint` | `#ECE8DF` | road markings and type |
| `concrete` | `#8B9098` | secondary text, waved-through traffic |
| `amber` | `#F2A900` | signage and caution: flagged, slowed, gate numbers |
| `stop` | `#E23B3B` | the barrier: turned back, held, banned |
| `pass` | `#3DAE6B` | clear traffic and trusted travellers |

**Type**: three roles. *Overpass* is based on the US highway sign alphabet, so
it's the natural face for anything on a sign. *Overpass Mono* is for addresses
and times. *Saira Stencil One* is for gate numbers and the name, stencilled like
road paint. All are self-hosted through `@fontsource`.

**Motion**: newly turned-back sources drive into the queue, booms rise and fall,
and the clear lane moves with the traffic. Under `prefers-reduced-motion` the
vehicles and the shimmer stop, and everything else appears in place.

## Reused from component-lab

| Component | Used for |
| --- | --- |
| `flickering-grid.tsx` | `ui/flickering-grid.tsx`: the clear lane's surface. Its flicker chance is fed the live packet rate, so the road shimmers with its traffic |
| `evervault-card.tsx` | `ui/evervault-card.tsx`: the passports in the holding bay. The hover reveals hex bytes under a red mask; the card now takes children instead of a single centred string |

Hand-built for this design instead: the lanes and barriers, gantry, traffic
counter, holding bay, pass office and inspection log. Considered and rejected:
`minimal` (the binary-matrix "ASCII art" is a looping video streamed from
21st.dev's CDN, not a component, and it can't show real traffic) and the
`stats-card` family (the lanes already carry the per-rule counts).

## Notes

- `recharts` is removed. Nothing uses it any more.
- The two old dashboards (`NIDSDashboard.tsx`, `NIPSDashboard.tsx`) are replaced
  by the single page with the Observe/Guard switch. The copy in
  `fake data version (for UI testing)/` is left as it was.
