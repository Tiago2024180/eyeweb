'use client';

import { useState } from 'react';
import Navbar from '@/components/Navbar';
import EyeIntro from '@/components/EyeIntro';
import Tabs from '@/components/Tabs';
import EmailChecker from '@/components/EmailChecker';
import UrlChecker from '@/components/UrlChecker';
import PasswordChecker from '@/components/PasswordChecker';

const TABS = [
  { id: 'email', label: 'Dados Pessoais', icon: 'fa-solid fa-envelope' },
  { id: 'url', label: 'Verificar URL', icon: 'fa-solid fa-link' },
  { id: 'password', label: 'Força da Password', icon: 'fa-solid fa-key' },
];

export default function Home() {
  const [showContent, setShowContent] = useState(false);
  const [activeTab, setActiveTab] = useState('email');

  const handleIntroComplete = () => {
    setShowContent(true);
  };

  return (
    <>
      {/* Animação do Olho */}
      <EyeIntro onComplete={handleIntroComplete} />

      {/* Conteúdo Principal */}
      <div className={`main-content ${showContent ? 'visible' : ''}`}>
        <Navbar />

        <div className="container">
          <header className="header">
            <h1>Eye Web</h1>
            <p className="tagline">Verifica se os teus dados foram expostos em fugas de dados</p>
          </header>

          <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab} />

          {/* Conteúdo das Tabs */}
          {activeTab === 'email' && (
            <section>
              <EmailChecker />
            </section>
          )}

          {activeTab === 'url' && (
            <section>
              <UrlChecker />
            </section>
          )}

          {activeTab === 'password' && (
            <section>
              <PasswordChecker />
            </section>
          )}
        </div>

        <footer className="footer">
          <p>Eye Web © 2025 - Projeto PAP</p>
          <p>Privacidade garantida com K-Anonymity</p>
        </footer>
      </div>
    </>
  );
}
