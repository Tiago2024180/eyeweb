import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';

export default function AboutPage() {
  return (
    <>
      <Navbar />
      
      <div className="container" style={{ maxWidth: '800px' }}>
        <header className="header">
          <h1>Sobre o Eye Web</h1>
          <p className="tagline">Conhece a nossa missão e equipa</p>
        </header>

        <nav className="about-nav">
          <a href="#mission">Missão</a>
          <a href="#vision">Visão</a>
          <a href="#team">Equipa</a>
          <a href="#privacy">Privacidade</a>
        </nav>

        <section id="mission" className="about-section">
          <h2>Missão</h2>
          <p>
            O Eye Web tem como missão fornecer uma ferramenta gratuita e acessível para que 
            qualquer pessoa possa verificar se os seus dados pessoais foram comprometidos em 
            fugas de dados conhecidas.
          </p>
          <p style={{ marginTop: '1rem' }}>
            Acreditamos que a segurança digital deve estar ao alcance de todos, sem custos 
            ocultos ou compromissos com a privacidade do utilizador.
          </p>
        </section>

        <section id="vision" className="about-section">
          <h2>Visão</h2>
          <p>
            Ambicionamos ser a referência em Portugal para verificação de fugas de dados, 
            educando os utilizadores sobre a importância da cibersegurança e oferecendo 
            ferramentas que respeitem a sua privacidade.
          </p>
          <p style={{ marginTop: '1rem' }}>
            O nosso objetivo é contribuir para uma internet mais segura, onde os utilizadores 
            estejam informados e protegidos contra ameaças digitais.
          </p>
        </section>

        <section id="team" className="about-section">
          <h2>Equipa</h2>
          <p>O Eye Web foi desenvolvido como Prova de Aptidão Profissional (PAP) por:</p>
          <ul className="team-list">
            <li>
              <strong>Samuel</strong>
              <em>Desenvolvedor Full-Stack & Arquiteto do Projeto</em>
            </li>
          </ul>
          <p style={{ marginTop: '1rem', color: 'var(--gray)' }}>
            Projeto desenvolvido no âmbito do curso de Técnico de Gestão e Programação 
            de Sistemas Informáticos.
          </p>
        </section>

        <section id="privacy" className="about-section">
          <h2>Como Protegemos a Tua Privacidade</h2>
          <p>
            O Eye Web utiliza o modelo de <strong>K-Anonymity</strong> para garantir que os 
            teus dados sensíveis nunca são transmitidos para os nossos servidores.
          </p>
          
          <div style={{ 
            background: 'var(--bg)', 
            padding: '1.5rem', 
            borderRadius: '8px', 
            marginTop: '1rem',
            border: '1px solid var(--gray)'
          }}>
            <h3 style={{ color: 'var(--blue)', marginBottom: '1rem' }}>Como Funciona:</h3>
            <ol style={{ paddingLeft: '1.25rem', lineHeight: '1.8' }}>
              <li>O teu email é convertido num hash SHA-256 <strong>localmente</strong> no teu browser</li>
              <li>Apenas os primeiros 5 caracteres do hash são enviados para a API</li>
              <li>A API devolve todas as entradas que começam com esse prefixo</li>
              <li>A comparação final é feita <strong>localmente</strong> no teu dispositivo</li>
            </ol>
          </div>
        </section>
      </div>

      <Footer />
    </>
  );
}