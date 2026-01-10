import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Eye Web - Breach Checker',
  description: 'Verifique se os seus dados foram expostos em fugas de dados. Ferramenta de cibersegurança com privacidade total usando K-Anonymity.',
  keywords: ['breach checker', 'data breach', 'cybersecurity', 'k-anonymity', 'email leak'],
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="pt">
      <head>
        <link 
          rel="stylesheet" 
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" 
        />
      </head>
      <body>{children}</body>
    </html>
  )
}
