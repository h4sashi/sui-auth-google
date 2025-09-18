// src/components/WalletConnection.tsx
'use client'

import { useState } from 'react'
import { ConnectButton, useWallet } from '@suiet/wallet-kit'
import { useWalletConnection } from '@/hooks/useWalletConnection'

export default function WalletConnection() {
  const [showUsernameSetup, setShowUsernameSetup] = useState(false)
  const [username, setUsername] = useState('')
  const [isSettingUsername, setIsSettingUsername] = useState(false)

  const { 
    wallet, 
    isConnecting, 
    connectionResult, 
    userProfile, 
    connectWallet, 
    setupUsername 
  } = useWalletConnection()

  const handleConnect = async () => {
    try {
      const result = await connectWallet()
      if (result.success && result.needsUsernameSetup) {
        setShowUsernameSetup(true)
      }
    } catch (error) {
      console.error('Connection failed:', error)
    }
  }

  const handleUsernameSetup = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSettingUsername(true)

    try {
      const result = await setupUsername(username)
      if (result.success) {
        setShowUsernameSetup(false)
        setUsername('')
      }
    } catch (error) {
      console.error('Username setup failed:', error)
    } finally {
      setIsSettingUsername(false)
    }
  }

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold text-center mb-6">Connect Your Sui Wallet</h2>

      {!wallet.connected ? (
        <div className="space-y-4">
          <ConnectButton 
            onConnectSuccess={handleConnect}
            className="w-full"
          />
          {isConnecting && (
            <div className="text-center text-blue-600">
              Connecting wallet...
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Connected Wallet Info */}
          <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
            <h3 className="text-green-800 font-semibold mb-2">✅ Wallet Connected</h3>
            <p className="text-sm text-green-700 break-all">
              {wallet.account?.address}
            </p>
            <p className="text-sm text-green-600 mt-1">
              Wallet: {wallet.adapter?.name}
            </p>
          </div>

          {/* Connection Result */}
          {connectionResult && (
            <div className={`p-4 rounded-lg border ${
              connectionResult.success 
                ? 'bg-green-50 border-green-200' 
                : 'bg-red-50 border-red-200'
            }`}>
              <p className={`text-sm ${
                connectionResult.success ? 'text-green-700' : 'text-red-700'
              }`}>
                {connectionResult.success ? connectionResult.message : connectionResult.error}
              </p>

              {connectionResult.blockchain && (
                <div className="mt-2 text-xs text-gray-600">
                  <p>Network: {connectionResult.blockchain.network}</p>
                  {connectionResult.blockchain.balanceFormatted && (
                    <p>Balance: {connectionResult.blockchain.balanceFormatted}</p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Username Setup Form */}
          {showUsernameSetup && (
            <form onSubmit={handleUsernameSetup} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                  Choose Your Username
                </label>
                <input
                  type="text"
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Enter username (3-20 characters)"
                  minLength={3}
                  maxLength={20}
                  pattern="[a-zA-Z0-9_-]+"
                  required
                />
                <p className="text-xs text-gray-500 mt-1">
                  Only letters, numbers, underscore, and hyphen allowed
                </p>
              </div>
              <button
                type="submit"
                disabled={isSettingUsername || username.length < 3}
                className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSettingUsername ? 'Setting Up...' : 'Set Username'}
              </button>
            </form>
          )}

          {/* User Profile Display */}
          {userProfile && !showUsernameSetup && (
            <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <h3 className="text-blue-800 font-semibold mb-2">👤 User Profile</h3>
              <p className="text-sm text-blue-700">Name: {userProfile.name}</p>
              <p className="text-sm text-blue-700">Auth Method: {userProfile.auth_method}</p>
              <p className="text-xs text-blue-600 mt-1 break-all">
                Profile ID: {userProfile.id}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}