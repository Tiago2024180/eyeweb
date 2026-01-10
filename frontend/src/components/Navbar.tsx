'use client';

import Link from 'next/link';

interface NavbarProps {
  showLogin?: boolean;
}

export default function Navbar({ showLogin = true }: NavbarProps) {
  return (
    <nav className="navbar">
      <Link href="/" className="logo-text">
        Eye Web
      </Link>
      <div className="navbar-right">
        <Link href="/about" className="nav-link">
          About
        </Link>
        {showLogin && (
          <Link href="/login" className="nav-link">
            <i className="fa-solid fa-user"></i>
          </Link>
        )}
      </div>
    </nav>
  );
}
