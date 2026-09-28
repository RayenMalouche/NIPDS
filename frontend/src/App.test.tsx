import React from 'react';
import { render, screen } from '@testing-library/react';
import App from './App';

beforeAll(() => {
  // jsdom lacks these; the clear lane's grid uses them.
  const Observer = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  (global as any).ResizeObserver = Observer;
  (global as any).IntersectionObserver = Observer;
  (global as any).fetch = jest.fn(() => Promise.reject(new Error('offline')));
  HTMLCanvasElement.prototype.getContext = jest.fn(() => null) as any;
});

test('renders the checkpoint in guard mode', () => {
  render(<App />);
  expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/checkpoint/i);
  expect(screen.getByRole('radio', { name: /guard/i })).toHaveAttribute('aria-checked', 'true');
  expect(screen.getByText(/holding bay/i)).toBeInTheDocument();
});
