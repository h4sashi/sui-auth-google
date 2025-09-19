// walletUtils.js - Server-side utilities for Wallet Standard integration
import { isValidSuiAddress } from '@mysten/sui/utils';

/**
 * Supported wallet providers with their metadata
 */
export const SUPPORTED_WALLETS = {
  'suiet': {
    name: 'Suiet Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'sui_wallet': {
    name: 'Sui Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'martian_sui_wallet': {
    name: 'Martian Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'glass_wallet': {
    name: 'Glass Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'ethos_wallet': {
    name: 'Ethos Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'nightly_wallet': {
    name: 'Nightly Wallet',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: ['standard:connect', 'standard:events', 'sui:signAndExecuteTransaction']
  },
  'manual': {
    name: 'Manual Entry',
    authMethod: 'manual_wallet',
    chains: ['sui:mainnet', 'sui:testnet', 'sui:devnet'],
    features: []
  }
};

/**
 * Validate wallet connection data
 * @param {Object} connectionData - Wallet connection data from client
 * @returns {Object} Validation result
 */
export function validateWalletConnection(connectionData) {
  const { walletAddress, walletName, signature, message, publicKey } = connectionData;
  
  // Basic required fields
  if (!walletAddress) {
    return { 
      valid: false, 
      error: 'Missing wallet address' 
    };
  }
  
  // Validate Sui address format
  if (!isValidSuiAddress(walletAddress)) {
    return { 
      valid: false, 
      error: 'Invalid Sui address format' 
    };
  }
  
  // Validate wallet name
  const normalizedWalletName = normalizeWalletName(walletName);
  if (!SUPPORTED_WALLETS[normalizedWalletName]) {
    console.warn(`Unknown wallet: ${walletName}, using manual_wallet auth method`);
  }
  
  return {
    valid: true,
    normalizedWalletName,
    walletInfo: SUPPORTED_WALLETS[normalizedWalletName] || SUPPORTED_WALLETS.manual
  };
}

/**
 * Normalize wallet name to match our supported wallet keys
 * @param {string} walletName - Raw wallet name from client
 * @returns {string} Normalized wallet name
 */
export function normalizeWalletName(walletName) {
  if (!walletName) return 'manual';
  
  const name = walletName.toLowerCase().replace(/\s+/g, '_');
  
  // Handle common variations
  const variations = {
    'suiet_wallet': 'suiet',
    'sui_wallet': 'sui_wallet',
    'martian_wallet': 'martian_sui_wallet',
    'martian_sui': 'martian_sui_wallet',
    'glass': 'glass_wallet',
    'ethos': 'ethos_wallet',
    'nightly': 'nightly_wallet'
  };
  
  return variations[name] || name;
}

/**
 * Get auth method for wallet
 * @param {string} walletName - Normalized wallet name
 * @returns {string} Auth method (zklogin or manual_wallet)
 */
export function getWalletAuthMethod(walletName) {
  const wallet = SUPPORTED_WALLETS[walletName];
  return wallet ? wallet.authMethod : 'manual_wallet';
}

/**
 * Validate public key format (if provided)
 * @param {any} publicKey - Public key from wallet
 * @returns {boolean} Whether public key is valid
 */
export function validatePublicKey(publicKey) {
  if (!publicKey) return true; // Optional field
  
  // Handle different public key formats
  if (Array.isArray(publicKey)) {
    return publicKey.every(byte => 
      Number.isInteger(byte) && byte >= 0 && byte <= 255
    );
  }
  
  if (typeof publicKey === 'string') {
    // Hex string validation
    return /^[0-9a-fA-F]+$/.test(publicKey) && publicKey.length % 2 === 0;
  }
  
  if (publicKey instanceof Uint8Array) {
    return publicKey.length > 0;
  }
  
  return false;
}

/**
 * Check if wallet connection requires signature verification
 * @param {string} walletName - Normalized wallet name
 * @returns {boolean} Whether signature is required
 */
export function requiresSignature(walletName) {
  // Manual entry doesn't require signature
  if (walletName === 'manual') return false;
  
  // For now, we're not requiring signatures for wallet connections
  // This can be enabled later for enhanced security
  return false;
}

/**
 * Format wallet connection for logging
 * @param {Object} connectionData - Wallet connection data
 * @returns {string} Formatted log message
 */
export function formatWalletConnectionLog(connectionData) {
  const { walletAddress, walletName } = connectionData;
  const shortAddress = walletAddress ? 
    `${walletAddress.substring(0, 6)}...${walletAddress.substring(walletAddress.length - 4)}` : 
    'unknown';
  
  return `${walletName || 'unknown'} - ${shortAddress}`;
}

/**
 * Generate temporary username for new wallet users
 * @param {string} walletAddress - Sui wallet address
 * @returns {string} Temporary username
 */
export function generateTempUsername(walletAddress) {
  if (!walletAddress) return 'Player_Unknown';
  
  const suffix = walletAddress.length >= 8 ? 
    walletAddress.substring(2, 10) : // Skip '0x' prefix
    walletAddress.substring(2);
  
  return `Player_${suffix}`;
}

/**
 * Check if username is auto-generated and needs setup
 * @param {string} name - Username to check
 * @returns {boolean} Whether username needs setup
 */
export function needsUsernameSetup(name) {
  if (!name) return true;
  
  // Check for auto-generated pattern
  const isAutoGenerated = name.startsWith('Player_') && name.length <= 16;
  return isAutoGenerated;
}