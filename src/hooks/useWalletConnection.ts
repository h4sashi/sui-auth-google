// src/hooks/useWalletConnection.ts
'use client'

import { useState } from 'react'
import { useWallet } from '@suiet/wallet-kit'
import { WalletConnectionResult, UserProfile } from '@/types/user'

export function useWalletConnection() {
  const [isConnecting, setIsConnecting] = useState(false)
  const [connectionResult, setConnectionResult] = useState<WalletConnectionResult | null>(null)
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null)

  const wallet = useWallet()

  const connectWallet = async (): Promise<WalletConnectionResult> => {
    if (!wallet.connected || !wallet.account?.address) {
      throw new Error('Wallet not connected')
    }

    setIsConnecting(true)
    setConnectionResult(null)

    try {
      const response = await fetch('/api/wallet-connect', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletAddress: wallet.account.address,
          walletName: wallet.adapter?.name || 'Unknown',
        }),
      })

      const result: WalletConnectionResult = await response.json()

      if (result.success && result.profile) {
        setUserProfile(result.profile as UserProfile)
      }

      setConnectionResult(result)
      return result

    } catch (error: any) {
      const errorResult: WalletConnectionResult = {
        success: false,
        error: error.message
      }
      setConnectionResult(errorResult)
      return errorResult
    } finally {
      setIsConnecting(false)
    }
  }

  const setupUsername = async (username: string): Promise<WalletConnectionResult> => {
    if (!wallet.account?.address) {
      throw new Error('Wallet not connected')
    }

    try {
      const response = await fetch('/api/setup-username', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          walletAddress: wallet.account.address,
          username: username,
        }),
      })

      const result: WalletConnectionResult = await response.json()

      if (result.success && result.profile) {
        setUserProfile(result.profile as UserProfile)
        setConnectionResult(result)
      }

      return result

    } catch (error: any) {
      return {
        success: false,
        error: error.message
      }
    }
  }

  return {
    wallet,
    isConnecting,
    connectionResult,
    userProfile,
    connectWallet,
    setupUsername,
  }
}