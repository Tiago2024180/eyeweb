'use client';

import { useState, useEffect } from 'react';
import './Avatar.css';

interface AvatarProps {
  src?: string | null;
  name?: string;
  email?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
  onClick?: () => void;
  showUploadHint?: boolean;
}

// Gera uma cor baseada no email/nome (consistente para o mesmo input)
function generateColor(input: string): string {
  // Cores vibrantes para os avatares
  const colors = [
    '#3b82f6', // blue
    '#8b5cf6', // violet
    '#ec4899', // pink
    '#ef4444', // red
    '#f97316', // orange
    '#eab308', // yellow
    '#22c55e', // green
    '#14b8a6', // teal
    '#06b6d4', // cyan
    '#6366f1', // indigo
  ];
  
  // Gerar um índice baseado no hash do input
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  
  const index = Math.abs(hash) % colors.length;
  return colors[index];
}

// Extrai as iniciais do nome ou email
function getInitials(name?: string, email?: string): string {
  if (name && name.trim()) {
    const parts = name.trim().split(' ');
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  }
  
  if (email) {
    const username = email.split('@')[0];
    return username.substring(0, 2).toUpperCase();
  }
  
  return 'US';
}

export default function Avatar({ 
  src, 
  name, 
  email, 
  size = 'md', 
  className = '',
  onClick,
  showUploadHint = false
}: AvatarProps) {
  const [imageError, setImageError] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  
  // Reset error when src changes
  useEffect(() => {
    setImageError(false);
  }, [src]);

  const initials = getInitials(name, email);
  const bgColor = generateColor(email || name || 'default');
  
  const sizeClasses = {
    sm: 'avatar-sm',
    md: 'avatar-md',
    lg: 'avatar-lg',
    xl: 'avatar-xl'
  };

  const hasValidImage = src && !imageError;
  const isClickable = !!onClick;

  return (
    <div 
      className={`avatar ${sizeClasses[size]} ${className} ${isClickable ? 'avatar-clickable' : ''}`}
      style={{ backgroundColor: hasValidImage ? 'transparent' : bgColor }}
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {hasValidImage ? (
        <img 
          src={src} 
          alt={name || 'Avatar'} 
          className="avatar-img"
          onError={() => setImageError(true)}
        />
      ) : (
        <span className="avatar-initials">{initials}</span>
      )}
      
      {/* Upload hint overlay */}
      {showUploadHint && isClickable && isHovered && (
        <div className="avatar-upload-overlay">
          <i className="fa-solid fa-camera"></i>
        </div>
      )}
    </div>
  );
}
