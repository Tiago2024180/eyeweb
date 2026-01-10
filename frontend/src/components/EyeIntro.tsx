'use client';

import { useState, useEffect, useCallback } from 'react';

interface EyeIntroProps {
  onComplete: () => void;
}

export default function EyeIntro({ onComplete }: EyeIntroProps) {
  const [clicked, setClicked] = useState(false);
  const [hidden, setHidden] = useState(false);
  const [pupilStyle, setPupilStyle] = useState({ transform: 'translate(-50%, -50%)' });

  // Seguir o cursor com a pupila
  const handleMouseMove = useCallback((e: MouseEvent) => {
    const eye = document.querySelector('.eye-container');
    if (!eye || clicked) return;

    const rect = eye.getBoundingClientRect();
    const eyeCenterX = rect.left + rect.width / 2;
    const eyeCenterY = rect.top + rect.height / 2;

    const deltaX = e.clientX - eyeCenterX;
    const deltaY = e.clientY - eyeCenterY;

    const maxMove = 30;
    const distance = Math.sqrt(deltaX ** 2 + deltaY ** 2);
    const factor = Math.min(distance / 200, 1);

    const moveX = (deltaX / distance) * maxMove * factor || 0;
    const moveY = (deltaY / distance) * maxMove * factor || 0;

    setPupilStyle({
      transform: `translate(calc(-50% + ${moveX}px), calc(-50% + ${moveY}px))`,
    });
  }, [clicked]);

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, [handleMouseMove]);

  const handleClick = () => {
    setClicked(true);
    
    // Após a animação, esconder e chamar onComplete
    setTimeout(() => {
      setHidden(true);
      onComplete();
    }, 1500);
  };

  return (
    <div className={`eye-screen ${hidden ? 'hidden' : ''}`}>
      <div 
        className={`eye-container ${clicked ? 'clicked' : ''}`}
        onClick={handleClick}
        title="Clica para entrar"
      >
        <div className="eye">
          <div className="pupil" style={pupilStyle}></div>
        </div>
      </div>
    </div>
  );
}
