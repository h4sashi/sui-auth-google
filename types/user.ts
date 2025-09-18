// types/user.ts
export interface UserProfile {
  id: string
  email?: string
  google_id?: string
  name: string
  picture?: string
  user_salt?: string
  sui_address: string
  auth_method: 'zklogin' | 'suiet_wallet' | 'manual_wallet'
  created_at: string
  updated_at: string
}

export interface WalletConnectionResult {
  success: boolean
  message?: string
  needsUsernameSetup?: boolean
  blockchain?: {
    verified: boolean
    balance: string
    balanceFormatted?: string
    network: string
    error?: string
  }
  profile?: UserProfile
  error?: string
}