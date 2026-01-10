/** @type {import('next').NextConfig} */
const nextConfig = {
  // Configurações do Next.js
  reactStrictMode: true,
  
  // Variáveis de ambiente públicas
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  },
}

module.exports = nextConfig
