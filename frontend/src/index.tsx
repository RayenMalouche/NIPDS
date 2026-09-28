import React from 'react';
import ReactDOM from 'react-dom/client';

import '@fontsource/overpass/400';
import '@fontsource/overpass/600';
import '@fontsource/overpass/800';
import '@fontsource/overpass-mono/400';
import '@fontsource/overpass-mono/600';
import '@fontsource/saira-stencil-one/400';
import './index.css';

import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
