import React, { useState, useEffect } from 'react';
import { WalletProvider, ConnectButton, useWallet } from '@suiet/wallet-kit';
import '@suiet/wallet-kit/style.css';

// Get STATE from URL params
const urlParams = new URLSearchParams(window.location.search);
const STATE = urlParams.get('state');

function WalletConnectionContent() {
  const [status, setStatus] = useState({ message: '', type: 'info' });
  const [isConnecting, setIsConnecting] = useState(false);
  const [manualAddress, setManualAddress] = useState('');
  
  const { 
    connected, 
    wallet, 
    address, 
    connect, 
    disconnect,
    getAccounts 
  } = useWallet();

  // Handle wallet connection
  useEffect(() => {
    if (connected && address && !isConnecting) {
      console.log('Wallet connected:', { wallet: wallet?.name, address });
      handleWalletConnected();
    }
  }, [connected, address, wallet]);

  const handleWalletConnected = async () => {
    if (isConnecting) return; // Prevent double execution
    
    setIsConnecting(true);
    setStatus({ message: 'Wallet connected successfully! Submitting to server...', type: 'success' });
    
    try {
      console.log('Submitting wallet connection:', {
        walletAddress: address,
        walletName: wallet?.name || 'unknown',
        state: STATE
      });

      const response = await fetch('/auth/wallet-connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletAddress: address,
          walletName: wallet?.name || 'suiet',
          signature: '',
          message: '',
          state: STATE,
          publicKey: ''
        })
      });

      const result = await response.json();
      console.log('Server response:', result);

      if (result.success) {
        setStatus({ 
          message: '✅ SUCCESS! Wallet connected successfully. You can close this window.',
          type: 'success' 
        });
        
        // Auto-close after delay
        setTimeout(() => { 
          try { 
            window.close(); 
          } catch(e) { 
            console.log('Cannot auto-close window'); 
          }
        }, 2000);
      } else {
        throw new Error(result.error || 'Unknown error');
      }
    } catch (error) {
      console.error('Connection submission failed:', error);
      setStatus({ 
        message: 'Connection failed: ' + error.message, 
        type: 'error' 
      });
    } finally {
      setIsConnecting(false);
    }
  };

  const handleManualConnection = async () => {
    if (!manualAddress.trim()) {
      setStatus({ message: 'Please enter a wallet address', type: 'error' });
      return;
    }

    if (!manualAddress.startsWith('0x') || manualAddress.length < 60) {
      setStatus({ message: 'Invalid Sui address format', type: 'error' });
      return;
    }

    setIsConnecting(true);
    setStatus({ message: 'Connecting manual wallet...', type: 'info' });

    try {
      const response = await fetch('/auth/wallet-connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletAddress: manualAddress.trim(),
          walletName: 'manual',
          signature: '',
          message: '',
          state: STATE
        })
      });

      const result = await response.json();

      if (result.success) {
        setStatus({ 
          message: '✅ SUCCESS! Manual wallet connected successfully. You can close this window.',
          type: 'success' 
        });
        
        setTimeout(() => { 
          try { 
            window.close(); 
          } catch(e) { 
            console.log('Cannot auto-close window'); 
          }
        }, 2000);
      } else {
        throw new Error(result.error || 'Unknown error');
      }
    } catch (error) {
      console.error('Manual connection failed:', error);
      setStatus({ 
        message: 'Manual connection failed: ' + error.message, 
        type: 'error' 
      });
    } finally {
      setIsConnecting(false);
    }
  };

  const validateManualAddress = (address) => {
    return address.startsWith('0x') && address.length >= 60;
  };

  return (
    <div style={{
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      margin: 0,
      padding: '20px',
      minHeight: '100vh',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center'
    }}>
      <div style={{
        background: 'white',
        padding: '40px',
        borderRadius: '15px',
        boxShadow: '0 10px 30px rgba(0,0,0,0.2)',
        maxWidth: '500px',
        width: '100%',
        textAlign: 'center'
      }}>
        <h1 style={{ color: '#333', fontSize: '28px', marginBottom: '20px', fontWeight: '600' }}>
          Connect Your Sui Wallet
        </h1>
        <p style={{ color: '#666', fontSize: '16px', marginBottom: '30px', lineHeight: '1.5' }}>
          Choose how you'd like to connect your Sui wallet to continue
        </p>
        
        {status.message && (
          <div style={{
            padding: '15px',
            borderRadius: '8px',
            margin: '20px 0',
            textAlign: 'center',
            fontWeight: '500',
            fontSize: '14px',
            background: status.type === 'success' ? '#d4edda' : 
                       status.type === 'error' ? '#f8d7da' : '#d1ecf1',
            color: status.type === 'success' ? '#155724' :
                   status.type === 'error' ? '#721c24' : '#0c5460',
            border: `1px solid ${status.type === 'success' ? '#c3e6cb' : 
                                 status.type === 'error' ? '#f5c6cb' : '#bee5eb'}`
          }}>
            {status.message}
          </div>
        )}

        {/* Suiet Kit Wallet Connection */}
        <div style={{
          margin: '30px 0',
          padding: '25px',
          border: '2px solid #e9ecef',
          borderRadius: '12px',
          background: '#f8f9fa'
        }}>
          <h3 style={{ margin: '0 0 20px 0', color: '#495057', fontSize: '18px' }}>
            🚀 Recommended: Use Wallet Extensions
          </h3>
          <p style={{ color: '#666', fontSize: '14px', marginBottom: '20px' }}>
            Connect with any supported Sui wallet extension
          </p>
          
          {!connected ? (
            <ConnectButton
              style={{
                background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
                color: 'white',
                border: 'none',
                padding: '16px 32px',
                borderRadius: '8px',
                fontSize: '16px',
                fontWeight: '600',
                cursor: 'pointer',
                width: '100%',
                transition: 'all 0.3s ease'
              }}
              disabled={isConnecting}
            >
              {isConnecting ? 'Connecting...' : 'Connect Wallet'}
            </ConnectButton>
          ) : (
            <div>
              <p style={{ color: '#28a745', fontWeight: '600', marginBottom: '10px' }}>
                ✅ Connected to {wallet?.name}
              </p>
              <div style={{
                background: '#e9ecef',
                padding: '10px',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'monospace',
                wordBreak: 'break-all',
                marginBottom: '15px'
              }}>
                {address}
              </div>
              <button
                onClick={disconnect}
                style={{
                  background: '#6c757d',
                  color: 'white',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  fontSize: '14px',
                  cursor: 'pointer'
                }}
              >
                Disconnect
              </button>
            </div>
          )}
        </div>

        {/* Divider */}
        <div style={{
          margin: '30px 0',
          textAlign: 'center',
          position: 'relative'
        }}>
          <div style={{
            position: 'absolute',
            top: '50%',
            left: 0,
            right: 0,
            height: '1px',
            background: '#e9ecef'
          }}></div>
          <span style={{
            background: 'white',
            padding: '0 15px',
            color: '#6c757d',
            fontSize: '14px'
          }}>
            OR
          </span>
        </div>

        {/* Manual Connection */}
        <div style={{
          margin: '30px 0',
          padding: '25px',
          border: '2px solid #e9ecef',
          borderRadius: '12px',
          background: '#f8f9fa'
        }}>
          <h3 style={{ margin: '0 0 20px 0', color: '#495057', fontSize: '18px' }}>
            📝 Manual Connection
          </h3>
          <p style={{ color: '#666', fontSize: '14px', marginBottom: '15px' }}>
            Enter your Sui wallet address directly
          </p>
          
          <input
            type="text"
            value={manualAddress}
            onChange={(e) => setManualAddress(e.target.value)}
            placeholder="Enter your Sui address (0x...)"
            style={{
              width: '100%',
              padding: '12px 16px',
              border: '2px solid #e9ecef',
              borderRadius: '8px',
              fontSize: '14px',
              margin: '10px 0',
              boxSizing: 'border-box',
              transition: 'border-color 0.3s ease'
            }}
            onFocus={(e) => e.target.style.borderColor = '#4f46e5'}
            onBlur={(e) => e.target.style.borderColor = '#e9ecef'}
          />
          
          <button
            onClick={handleManualConnection}
            disabled={!validateManualAddress(manualAddress) || isConnecting}
            style={{
              background: validateManualAddress(manualAddress) && !isConnecting 
                ? 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)' 
                : '#6c757d',
              color: 'white',
              border: 'none',
              padding: '16px 32px',
              borderRadius: '8px',
              fontSize: '16px',
              fontWeight: '600',
              cursor: validateManualAddress(manualAddress) && !isConnecting ? 'pointer' : 'not-allowed',
              width: '100%',
              transition: 'all 0.3s ease'
            }}
          >
            {isConnecting ? 'Connecting...' : 'Connect Manual Wallet'}
          </button>
        </div>
      </div>
    </div>
  );
}

function App() {
  if (!STATE) {
    return (
      <div style={{ padding: '50px', textAlign: 'center' }}>
        <h1>Error: Missing state parameter</h1>
        <p>This page requires a valid state parameter to function.</p>
      </div>
    );
  }

  return (
    <WalletProvider>
      <WalletConnectionContent />
    </WalletProvider>
  );
}

export default App;