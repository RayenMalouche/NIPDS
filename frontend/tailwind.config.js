/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      // One palette, strict roles — see README "The design".
      colors: {
        asphalt: '#1C1F23', // page ground: the road at night
        tarmac: '#262A30', // panels, lanes
        paint: '#ECE8DF', // road markings and type
        concrete: '#8B9098', // secondary text, raised barriers, waved-through
        amber: '#F2A900', // signage and caution: flagged, slowed
        stop: '#E23B3B', // the barrier: turned back, held, banned
        pass: '#3DAE6B', // trusted travellers, barrier up
      },
      fontFamily: {
        sign: ['Overpass', 'system-ui', 'sans-serif'],
        mono: ['"Overpass Mono"', 'ui-monospace', 'monospace'],
        stencil: ['"Saira Stencil One"', 'Impact', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
