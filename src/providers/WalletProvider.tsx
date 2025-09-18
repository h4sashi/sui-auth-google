// src/providers/WalletProvider.tsx
'use client'

import { WalletProvider } from '@suiet/wallet-kit'
import { SuiDevnetChain, SuiTestnetChain, SuiMainnetChain } from '@suiet/wallet-kit'
import '@suiet/wallet-kit/style.css'

const chains = [SuiDevnetChain, SuiTestnetChain, SuiMainnetChain]

export default function WalletContextProvider({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <WalletProvider chains={chains} autoConnect>
      {children}
    </WalletProvider>
  )
}