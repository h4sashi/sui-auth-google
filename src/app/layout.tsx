import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import WalletContextProvider from '@/providers/WalletProvider'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Sui Wallet Connection App',
  description: 'Connect your Sui wallet using Suiet Wallet Kit',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <WalletContextProvider>
          {children}
        </WalletContextProvider>
      </body>
    </html>
  )
}