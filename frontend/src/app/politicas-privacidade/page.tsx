"use client";
import React from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';

export default function PoliticasPrivacidadePage() {
  return (
    <>
      <Navbar />
      <div className="container" style={{ maxWidth: '900px', margin: '0 auto', padding: '2rem 1.5rem' }}>
        <header style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 700 }}>Políticas de Privacidade</h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', marginTop: '0.5rem' }}>
            Última atualização: Fevereiro 2026
          </p>
        </header>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>1. Introdução</h2>
          <p>
            O Eye Web Reborn compromete-se a proteger a privacidade dos seus utilizadores. Esta política descreve como
            recolhemos, utilizamos e protegemos as informações quando utiliza a nossa plataforma.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>2. Dados que NÃO recolhemos</h2>
          <p>O Eye Web foi concebido com o princípio de privacidade por design:</p>
          <ul style={{ marginLeft: '1.5rem', marginTop: '0.75rem', color: '#fff', lineHeight: '1.8' }}>
            <li><strong>E-mails:</strong> Nunca são enviados para o servidor. A verificação usa o modelo K-Anonymity — apenas um prefixo do hash SHA-256 é transmitido.</li>
            <li><strong>Passwords:</strong> Nunca saem do seu navegador. A verificação é feita localmente comparando hashes.</li>
            <li><strong>URLs verificados:</strong> São analisados de forma encriptada e os resultados são cacheados sem associação ao utilizador.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>3. Dados que recolhemos</h2>
          <p>Para o funcionamento do sistema de monitorização de tráfego e segurança:</p>
          <ul style={{ marginLeft: '1.5rem', marginTop: '0.75rem', color: '#fff', lineHeight: '1.8' }}>
            <li><strong>Endereço IP:</strong> Registado para deteção de ameaças e proteção contra ataques.</li>
            <li><strong>Geolocalização aproximada:</strong> Apenas país e cidade, determinados a partir do IP público.</li>
            <li><strong>User-Agent:</strong> Para identificar tipo de dispositivo e detetar scanners maliciosos.</li>
            <li><strong>Páginas visitadas:</strong> Apenas o caminho (path), sem dados pessoais.</li>
          </ul>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>4. Segurança</h2>
          <p>
            Todas as comunicações são encriptadas com HTTPS. Os dados de tráfego são limpos automaticamente ao final
            de cada dia. Implementamos rate limiting, deteção de scanners, proteção contra SQL injection e bloqueio
            automático de IPs maliciosos.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>5. Cookies</h2>
          <p>
            Utilizamos apenas cookies essenciais para a sessão de autenticação (Supabase Auth). Não utilizamos
            cookies de rastreamento, analytics de terceiros ou publicidade.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>6. Contacto</h2>
          <p>
            Para questões sobre privacidade, contacte-nos em{' '}
            <a href="mailto:suporte@eyeweb.pt" style={{ color: '#90caf9', fontWeight: 'bold' }}>
              suporte@eyeweb.pt
            </a>.
          </p>
        </section>
      </div>
      <Footer />
    </>
  );
}
