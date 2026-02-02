'use client';

import Link from 'next/link';

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="site-footer-minimal">
      <div className="footer-minimal-content">
        <div className="footer-minimal-links">
          <Link href="/politicas-privacidade">Políticas e Privacidade</Link>
          <span className="footer-divider">|</span>
          <Link href="/termos-servico">Termos de Serviço</Link>
          <span className="footer-divider">|</span>
          <a href="mailto:suporte@eyeweb.pt">suporte@eyeweb.pt</a>
        </div>
        <div className="footer-minimal-info">
          <span>© {currentYear} Eye Web</span>
          <span className="footer-divider">·</span>
          <span>Privacidade garantida com <a href="https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange" target="_blank" rel="noopener noreferrer" className="k-anonymity-link">K-Anonymity</a></span>
        </div>
      </div>
    </footer>
  );
}
