"use client";
import React from 'react';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';

export default function TermosServicoPage() {
  return (
    <>
      <Navbar />
      <div className="container" style={{ maxWidth: '900px', margin: '0 auto', padding: '2rem 1.5rem' }}>
        <header style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
          <h1 style={{ fontSize: '2rem', fontWeight: 700 }}>Termos de Serviço</h1>
          <p style={{ color: 'rgba(255,255,255,0.5)', marginTop: '0.5rem' }}>
            Última atualização: Fevereiro 2026
          </p>
        </header>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>1. Aceitação dos Termos</h2>
          <p>
            Ao aceder e utilizar o Eye Web Reborn, concorda com estes Termos de Serviço. Se não concordar com
            alguma parte, não deve utilizar a plataforma.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>2. Descrição do Serviço</h2>
          <p>O Eye Web Reborn é uma plataforma de cibersegurança que oferece:</p>
          <ul style={{ marginLeft: '1.5rem', marginTop: '0.75rem', color: '#fff', lineHeight: '1.8' }}>
            <li>Verificação de e-mails em bases de dados de fugas de dados (data breaches)</li>
            <li>Auditoria de segurança de palavras-passe</li>
            <li>Análise de segurança de URLs e websites</li>
            <li>Monitorização de tráfego e deteção de ameaças</li>
          </ul>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>3. Utilização Adequada</h2>
          <p>O utilizador compromete-se a:</p>
          <ul style={{ marginLeft: '1.5rem', marginTop: '0.75rem', color: '#fff', lineHeight: '1.8' }}>
            <li>Utilizar a plataforma apenas para fins legítimos de verificação de segurança</li>
            <li>Não tentar comprometer, sobrecarregar ou atacar os serviços</li>
            <li>Não utilizar ferramentas automatizadas para scraping ou abuso dos endpoints</li>
            <li>Verificar apenas dados que lhe pertençam ou para os quais tenha autorização</li>
          </ul>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>4. Privacidade e Segurança</h2>
          <p>
            A plataforma foi desenhada com o modelo K-Anonymity, garantindo que os seus dados nunca são
            transmitidos em texto claro. Para mais detalhes, consulte a nossa{' '}
            <a href="/politicas-privacidade" style={{ color: '#90caf9', fontWeight: 'bold' }}>
              Política de Privacidade
            </a>.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>5. Limitação de Responsabilidade</h2>
          <p>
            O Eye Web Reborn é fornecido &quot;tal como está&quot;. Embora nos esforcemos para manter informações precisas
            e atualizadas, não garantimos que os resultados de verificação sejam 100% completos. A ausência de
            resultados não garante que os dados nunca foram comprometidos.
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>6. Bloqueio de Acesso</h2>
          <p>
            Reservamo-nos o direito de bloquear automaticamente qualquer IP que apresente comportamento malicioso,
            incluindo mas não limitado a: tentativas de SQL injection, scanning de vulnerabilidades, brute force,
            ou excesso de requests (DDoS).
          </p>
        </section>

        <section style={{ marginBottom: '2rem' }}>
          <h2 style={{ color: '#e53935', fontWeight: 'bold', marginBottom: '0.75rem' }}>7. Contacto</h2>
          <p>
            Para questões sobre estes termos, contacte-nos em{' '}
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
