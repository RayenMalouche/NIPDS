// From component-lab `evervault-card.tsx` (21st.dev). Kept: the random-character
// field revealed under a cursor-following radial mask. Changed: the characters
// are hex (packet bytes, not base-62), the reveal gradient is the barrier's red
// instead of green-to-blue, the card is square-cornered, and it takes children
// instead of a single centred string — here it's the passport of a held IP.
import React, { useEffect, useState } from 'react';
import { motion, useMotionTemplate, useMotionValue, MotionValue } from 'framer-motion';

import { cn } from '../../lib/cn';

const characters = '0123456789ABCDEF';
export const generateRandomString = (length: number) => {
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
    if (i % 2 === 1) result += ' ';
  }
  return result;
};

export function EvervaultCard({ children, className }: { children: React.ReactNode; className?: string }) {
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const [randomString, setRandomString] = useState('');

  useEffect(() => setRandomString(generateRandomString(900)), []);

  function onMouseMove({ currentTarget, clientX, clientY }: React.MouseEvent<HTMLDivElement>) {
    const { left, top } = currentTarget.getBoundingClientRect();
    mouseX.set(clientX - left);
    mouseY.set(clientY - top);
    setRandomString(generateRandomString(900));
  }

  return (
    <div onMouseMove={onMouseMove} className={cn('group/card relative overflow-hidden', className)}>
      <CardPattern mouseX={mouseX} mouseY={mouseY} randomString={randomString} />
      <div className="relative z-10">{children}</div>
    </div>
  );
}

function CardPattern({ mouseX, mouseY, randomString }: { mouseX: MotionValue<number>; mouseY: MotionValue<number>; randomString: string }) {
  const maskImage = useMotionTemplate`radial-gradient(180px at ${mouseX}px ${mouseY}px, white, transparent)`;
  const style = { maskImage, WebkitMaskImage: maskImage };
  return (
    <div className="pointer-events-none" aria-hidden>
      <motion.div
        className="absolute inset-0 bg-gradient-to-br from-stop/70 to-stop/10 opacity-0 transition duration-500 group-hover/card:opacity-100"
        style={style}
      />
      <motion.div className="absolute inset-0 opacity-0 mix-blend-overlay group-hover/card:opacity-100" style={style}>
        <p className="absolute inset-x-0 h-full whitespace-pre-wrap break-words font-mono text-[0.65rem] font-semibold leading-4 text-paint">
          {randomString}
        </p>
      </motion.div>
    </div>
  );
}
