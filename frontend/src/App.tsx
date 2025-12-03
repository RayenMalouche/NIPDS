import React, { useState } from 'react';
import NIDSDashboard from './components/NIDSDashboard';
import NIPSDashboard from './components/NIPSDashboard';
import './App.css'; // Optional

function App() {
  const [view, setView] = useState<'nids' | 'nips'>('nips'); // Default to NIPS

  return (
    <div className="App">
      <div className="flex justify-center space-x-4 mb-6 pt-4">
        <button
          onClick={() => setView('nids')}
          className={`px-6 py-2 rounded-lg font-semibold transition ${
            view === 'nids' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          NIDS Dashboard (Detection Only)
        </button>
        <button
          onClick={() => setView('nips')}
          className={`px-6 py-2 rounded-lg font-semibold transition ${
            view === 'nips' ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          NIPS Dashboard (Detection + Prevention)
        </button>
      </div>
      {view === 'nids' ? <NIDSDashboard /> : <NIPSDashboard />}
    </div>
  );
}

export default App;