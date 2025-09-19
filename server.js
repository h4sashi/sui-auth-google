// server.js - Refactored with external HTML template
// git add . && git commit -m "Wallet Fix" && git push origin main
// server.js - Updated with Wallet Standard integration
import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { jwtDecode } from "jwt-decode";
import { generateRandomness, jwtToAddress } from "@mysten/sui/zklogin";
import { isValidSuiAddress } from "@mysten/sui/utils";
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

import supabase from "./supabaseClient.js";
import {
  validateWalletConnection,
  getWalletAuthMethod,
  formatWalletConnectionLog,
  generateTempUsername,
  needsUsernameSetup,
  validatePublicKey
} from "./walletUtils.js";

// Get current directory for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

// Network Configuration
const NETWORK_CONFIG = {
  current: process.env.SUI_NETWORK || 'testnet',
  devnet: 'https://fullnode.devnet.sui.io',
  testnet: 'https://fullnode.testnet.sui.io', 
  mainnet: 'https://fullnode.mainnet.sui.io'
};

// Initialize Sui Client
const suiClient = new SuiClient({ 
  url: getFullnodeUrl(NETWORK_CONFIG.current) 
});

console.log(`Connected to Sui ${NETWORK_CONFIG.current.toUpperCase()} network`);

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(bodyParser.json());

// Enhanced request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  if (req.body && Object.keys(req.body).length > 0) {
    // Sanitize sensitive data for logging
    const sanitizedBody = { ...req.body };
    if (sanitizedBody.signature) sanitizedBody.signature = '[SIGNATURE]';
    if (sanitizedBody.publicKey) sanitizedBody.publicKey = '[PUBLIC_KEY]';
    console.log('Request Body:', JSON.stringify(sanitizedBody, null, 2));
  }
  next();
});

const PORT = process.env.PORT || 3000;
const sessions = {}; // { state: profile }

// Template loading helper function
function loadTemplate(templateName, replacements = {}) {
  try {
    const templatePath = join(__dirname, 'templates', templateName);
    let template = readFileSync(templatePath, 'utf8');
    
    // Replace placeholders with actual values
    for (const [placeholder, value] of Object.entries(replacements)) {
      const regex = new RegExp(`{{${placeholder}}}`, 'g');
      template = template.replace(regex, value);
    }
    
    return template;
  } catch (error) {
    console.error(`Error loading template ${templateName}:`, error);
    return `<html><body><h1>Template Error</h1><p>Could not load template: ${templateName}</p></body></html>`;
  }
}

// Wallet connection page using external template
app.get("/wallet-connect", (req, res) => {
  // Redirect to the external wallet connect page
  res.redirect("https://sui-frontend-nu.vercel.app/");
});

// Enhanced wallet connection endpoint with Wallet Standard support
app.post("/auth/wallet-connect", async (req, res) => {
  console.log("🔗 Wallet Standard connection request received");
  
  try {
    const connectionData = req.body;
    const { walletAddress, walletName, state } = connectionData;
    
    // Basic validation
    if (!state) {
      console.log("Missing state parameter");
      return res.status(400).json({
        success: false,
        error: "Missing state parameter"
      });
    }
    
      const validation = validateWalletConnection(connectionData);
      if (!validation.valid) {
        console.log("Wallet validation failed:", validation.error);
        return res.status(400).json({
          success: false,
          error: validation.error
        });
      }
    
    const { normalizedWalletName, walletInfo } = validation;
    const authMethod = getWalletAuthMethod(normalizedWalletName);
    
      console.log(`Valid wallet connection: ${formatWalletConnectionLog(connectionData)}`);
      console.log(`Auth method: ${authMethod} (${walletInfo.name})`);
    
    // Validate public key if provided
    if (connectionData.publicKey && !validatePublicKey(connectionData.publicKey)) {
      console.warn("⚠️ Invalid public key format provided, ignoring");
      delete connectionData.publicKey;
    }
    
    // Check blockchain status with enhanced error handling
    let blockchainInfo = {
      exists: false,
      balance: '0',
      hasActivity: false,
      network: NETWORK_CONFIG.current,
      error: null
    };
    
    try {
      console.log('🔗 Verifying wallet on blockchain...');
      
      const [balance, objects] = await Promise.all([
        suiClient.getBalance({
          owner: walletAddress,
          coinType: '0x2::sui::SUI'
        }),
        suiClient.getOwnedObjects({
          owner: walletAddress,
          limit: 1
        })
      ]);
      
      blockchainInfo = {
        exists: true,
        balance: balance.totalBalance,
        balanceFormatted: (parseInt(balance.totalBalance) / 1_000_000_000).toFixed(4) + ' SUI',
        hasActivity: parseInt(balance.totalBalance) > 0 || objects.data.length > 0,
        network: NETWORK_CONFIG.current
      };
      
        console.log(`Blockchain verified: ${blockchainInfo.balanceFormatted}`);
      
    } catch (blockchainError) {
        console.log(`Blockchain verification failed: ${blockchainError.message}`);
      blockchainInfo.error = blockchainError.message;
    }
    
    // Check for existing user profile
    let { data: existingProfile, error: queryError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("sui_address", walletAddress)
      .single();
    
    if (queryError && queryError.code !== 'PGRST116') {
        console.error("Database query error:", queryError);
      return res.status(500).json({ 
        success: false,
        error: "Database query failed" 
      });
    }
    
    let finalProfile;
    let isNewUser = false;
    
    if (existingProfile) {
        console.log("Found existing user profile:", existingProfile.id);
      
      // Update existing profile with new connection info
      const updateData = {
        updated_at: new Date().toISOString(),
        auth_method: authMethod
      };
      
      // Update wallet name if it's more specific than stored
      if (walletInfo.name !== 'Manual Entry' && 
          (!existingProfile.wallet_name || existingProfile.wallet_name === 'manual')) {
        updateData.wallet_name = normalizedWalletName;
      }
      
      const { data: updated, error: updateError } = await supabase
        .from("user_profiles")
        .update(updateData)
        .eq("id", existingProfile.id)
        .select()
        .single();
        
      if (updateError) {
          console.error("Profile update error:", updateError);
        return res.status(500).json({ 
          success: false,
          error: "Profile update failed" 
        });
      }
      
      finalProfile = updated;
        console.log("Existing user profile updated");
    } else {
        console.log("Creating new user profile for wallet connection");
      
      const tempName = generateTempUsername(walletAddress);
      
      const profileData = {
        email: null,
        google_id: null,
        name: tempName,
        picture: null,
        user_salt: null,
        sui_address: walletAddress,
        auth_method: authMethod,
        wallet_name: normalizedWalletName,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
        console.log("Profile data to insert:", JSON.stringify(profileData, null, 2));
      
      const { data: inserted, error: insertError } = await supabase
        .from("user_profiles")
        .insert([profileData])
        .select()
        .single();
        
      if (insertError) {
          console.error("Profile insert error:", insertError);
        return res.status(500).json({ 
          success: false,
          error: "Profile creation failed: " + insertError.message 
        });
      }
      
      finalProfile = inserted;
      isNewUser = true;
        console.log("New user profile created:", finalProfile.id);
    }
    
    const requiresUsername = needsUsernameSetup(finalProfile.name);
    console.log(`Username setup needed: ${requiresUsername}`);
    
    // Create session for Unity polling
    const sessionData = {
      id: finalProfile.id,
      email: finalProfile.email,
      name: finalProfile.name,
      picture: finalProfile.picture,
      suiWallet: walletAddress,
      authMethod: authMethod,
      walletName: normalizedWalletName,
      profileId: finalProfile.id,
      needsUsernameSetup: requiresUsername
    };
    
    // Store session for Unity polling
    sessions[state] = sessionData;
      console.log("Session stored with state:", state);
    
    const responseData = {
      success: true,
      message: isNewUser ? "New wallet connected successfully" : "Wallet reconnected successfully",
      needsUsernameSetup: requiresUsername,
      blockchain: {
        verified: blockchainInfo.exists,
        balance: blockchainInfo.balance,
        balanceFormatted: blockchainInfo.balanceFormatted,
        network: blockchainInfo.network,
        error: blockchainInfo.error
      },
      profile: {
        id: finalProfile.id,
        name: finalProfile.name,
        suiWallet: walletAddress,
        authMethod: authMethod,
        walletName: normalizedWalletName,
        profileId: finalProfile.id,
        needsUsernameSetup: requiresUsername
      },
      walletStandard: {
        supported: true,
        version: "1.0.3"
      }
    };
    
      console.log("Sending success response");
    res.json(responseData);
    
  } catch (err) {
      console.error("Wallet connection error:", err);
    res.status(500).json({ 
      success: false,
      error: "Wallet connection failed: " + err.message 
    });
  }
});

// Enhanced username setup endpoint
app.post("/setup-username", async (req, res) => {
  const { walletAddress, username } = req.body;
  
  try {
    if (!walletAddress || !username) {
      return res.status(400).json({
        success: false,
        error: "Wallet address and username are required"
      });
    }
    
    // Validate wallet address
    if (!isValidSuiAddress(walletAddress)) {
      return res.status(400).json({
        success: false,
        error: "Invalid Sui address format"
      });
    }
    
    const trimmedUsername = username.trim();
    
    // Username validation
    if (trimmedUsername.length < 3 || trimmedUsername.length > 20) {
      return res.status(400).json({
        success: false,
        error: "Username must be between 3 and 20 characters"
      });
    }
    
    if (!/^[a-zA-Z0-9_-]+$/.test(trimmedUsername)) {
      return res.status(400).json({
        success: false,
        error: "Username can only contain letters, numbers, underscore, and hyphen"
      });
    }
    
    // Check for username conflicts
    const { data: existingUser, error: checkError } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("name", trimmedUsername)
      .neq("sui_address", walletAddress)
      .single();
    
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: "Username already taken"
      });
    }
    
    // Update username
    const { data: updatedProfile, error: updateError } = await supabase
      .from("user_profiles")
      .update({ 
        name: trimmedUsername,
        updated_at: new Date().toISOString()
      })
      .eq("sui_address", walletAddress)
      .select()
      .single();
      
    if (updateError) {
      console.error("Username update error:", updateError);
      return res.status(500).json({
        success: false,
        error: "Failed to update username"
      });
    }
    
      console.log(`Username updated: ${walletAddress} -> ${trimmedUsername}`);
    
    res.json({
      success: true,
      message: "Username updated successfully",
      profile: {
        id: updatedProfile.id,
        name: updatedProfile.name,
        suiWallet: updatedProfile.sui_address,
        authMethod: updatedProfile.auth_method,
        walletName: updatedProfile.wallet_name,
        profileId: updatedProfile.id,
        needsUsernameSetup: false
      }
    });
    
  } catch (err) {
    console.error("Username setup error:", err);
    res.status(500).json({
      success: false,
      error: "Username setup failed: " + err.message
    });
  }
});

// Google OAuth callback (unchanged)
app.get("/auth/google/callback", async (req, res) => {
    const { code, state } = req.query;
    
    if (!code) {
        console.error("No authorization code received");
        return res.status(400).send("Authorization failed - no code");
    }

    try {
        console.log("Processing Google OAuth callback...");
        
        const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: process.env.REDIRECT_URI,
                grant_type: "authorization_code"
            })
        });

        const tokens = await tokenResponse.json();
        if (!tokens.id_token) {
            throw new Error("No ID token received");
        }

        const userInfo = jwtDecode(tokens.id_token);
        console.log("User info:", {
            sub: userInfo.sub,
            email: userInfo.email,
            name: userInfo.name
        });

        let profile;
        let isNewUser = false;

        const { data: existingProfile, error: fetchError } = await supabase
            .from("user_profiles")
            .select("*")
            .eq("google_id", userInfo.sub)
            .single();

        if (existingProfile) {
            console.log("Existing zkLogin user found - checking if username needs preservation");
            
            const hasCustomUsername = existingProfile.name && 
                                    !existingProfile.name.startsWith('Player_') &&
                                    existingProfile.name !== userInfo.name;
            
            console.log(`Existing name: "${existingProfile.name}"`);
            console.log(`Google name: "${userInfo.name}"`);
            console.log(`Has custom username: ${hasCustomUsername}`);
            
            const updateData = {
                updated_at: new Date().toISOString(),
                picture: userInfo.picture,
                email: userInfo.email
            };
            
            if (!hasCustomUsername) {
                updateData.name = userInfo.name;
                console.log("No custom username detected - updating name from Google profile");
            } else {
                console.log("Custom username detected - preserving existing name");
            }

            const { data: updatedProfile, error: updateError } = await supabase
                .from("user_profiles")
                .update(updateData)
                .eq("id", existingProfile.id)
                .select()
                .single();

            if (updateError) {
                console.error("Profile update error:", updateError);
                throw new Error("Profile update failed");
            }

            profile = updatedProfile;
            console.log(`Final profile name: "${profile.name}"`);
            console.log(`Retrieved existing Sui address: ${profile.sui_address}`);
            
        } else {
            console.log("New zkLogin user - creating profile");
            
            const userSalt = generateRandomness();
            const suiAddress = jwtToAddress(tokens.id_token, userSalt);
            console.log("Generated new Sui address:", suiAddress);

            const profileData = {
                email: userInfo.email,
                google_id: userInfo.sub,
                name: userInfo.name,
                picture: userInfo.picture,
                user_salt: userSalt,
                sui_address: suiAddress,
                auth_method: "zklogin",
                wallet_name: "zklogin",
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            };

            const { data: insertedProfile, error: insertError } = await supabase
                .from("user_profiles")
                .insert([profileData])
                .select()
                .single();

            if (insertError) {
                console.error("Profile insert error:", insertError);
                throw new Error("Profile creation failed");
            }

            profile = insertedProfile;
            isNewUser = true;
        }

        const requiresUsername = needsUsernameSetup(profile.name);

        sessions[state] = {
            id: userInfo.sub,
            email: userInfo.email,
            name: profile.name,
            picture: userInfo.picture,
            suiWallet: profile.sui_address,
            authMethod: "zklogin",
            walletName: "zklogin",
            profileId: profile.id,
            sub: userInfo.sub,
            aud: userInfo.aud,
            needsUsernameSetup: requiresUsername
        };

        try {
            console.log("Checking Sui balance for zkLogin user...");
            const balance = await suiClient.getBalance({
                owner: profile.sui_address,
                coinType: '0x2::sui::SUI'
            });
            const formattedBalance = (parseInt(balance.totalBalance) / 1_000_000_000).toFixed(4);
            console.log("Sui Balance: " + formattedBalance + " SUI (" + balance.totalBalance + " MIST)");
        } catch (balanceError) {
            console.log("Could not fetch balance: " + balanceError.message + " (This is normal for new addresses)");
        }

        console.log("zkLogin successful for " + userInfo.email + " - " + (isNewUser ? 'New user created' : 'Existing user logged in'));
        
        const welcomeMessage = isNewUser ?
            "Welcome to the game, " + profile.name + "!" :
            "Welcome back, " + profile.name + "!";

        // Load success template
        const html = loadTemplate('zklogin-success.html', {
            WELCOME_MESSAGE: welcomeMessage,
            SUI_ADDRESS: profile.sui_address
        });

        res.send(html);

    } catch (err) {
        console.error("OAuth callback error:", err);
        
        // Load error template
        const html = loadTemplate('auth-error.html', {
            ERROR_MESSAGE: err.message
        });

        res.status(500).send(html);
    }
});

// Enhanced wallet validation endpoint
app.post("/validate-wallet", async (req, res) => {
  console.log("🔍 Wallet validation request received");
  
  try {
    const { address } = req.body;
    
    if (!address) {
      console.log("No address provided");
      return res.status(400).json({
        valid: false,
        address: null,
        message: "No wallet address provided"
      });
    }
    
    const cleanAddress = address.trim();
    console.log(`🔍 Validating address: ${cleanAddress}`);
    
    const isValidFormat = isValidSuiAddress(cleanAddress);
    console.log(`Address format validation: ${isValidFormat}`);
    
    let blockchainInfo = {
      exists: false,
      balance: '0',
      hasActivity: false,
      error: null
    };
    
    if (isValidFormat) {
      try {
        console.log('🔗 Checking blockchain status...');
        
        const [balance, objects] = await Promise.all([
          suiClient.getBalance({
            owner: cleanAddress,
            coinType: '0x2::sui::SUI'
          }),
          suiClient.getOwnedObjects({
            owner: cleanAddress,
            limit: 1
          })
        ]);
        
        blockchainInfo = {
          exists: true,
          balance: balance.totalBalance,
          balanceFormatted: (parseInt(balance.totalBalance) / 1_000_000_000).toFixed(4) + ' SUI',
          hasActivity: parseInt(balance.totalBalance) > 0 || objects.data.length > 0,
          network: NETWORK_CONFIG.current
        };
        
        console.log(`✅ Blockchain info:`, blockchainInfo);
        
      } catch (blockchainError) {
        console.log(`⚠️ Blockchain check failed: ${blockchainError.message}`);
        blockchainInfo.error = blockchainError.message;
      }
    }
    
    const responseData = {
      valid: isValidFormat,
      address: cleanAddress,
      message: isValidFormat 
        ? (blockchainInfo.exists 
           ? `Valid Sui address (Balance: ${blockchainInfo.balanceFormatted})` 
           : 'Valid Sui address (Not yet active on blockchain)')
        : "Invalid Sui address format",
      blockchain: blockchainInfo,
      network: NETWORK_CONFIG.current,
      walletStandard: {
        supported: true,
        version: "1.0.3"
      }
    };
    
    console.log("Sending validation response:", responseData);
    res.json(responseData);
    
  } catch (err) {
    console.error("Validation error:", err);
    res.status(500).json({
      valid: false,
      address: req.body?.address || null,
      message: "Server error during validation: " + err.message
    });
  }
});

// Unity polling endpoint (unchanged)
app.get("/getProfile", (req, res) => {
  const { state } = req.query;
  if (sessions[state]) {
    res.json(sessions[state]);
    delete sessions[state];
  } else {
    res.status(404).send("Not ready");
  }
});

// Enhanced health check
app.get("/ping", async (req, res) => {
  try {
    const chainId = await suiClient.getChainIdentifier();
    res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      message: "Server is running with Wallet Standard support",
      network: NETWORK_CONFIG.current,
      chainId,
      walletStandard: {
        supported: true,
        version: "1.0.3"
      }
    });
  } catch (err) {
    res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      message: "Server is running with Wallet Standard support",
      networkError: err.message,
      walletStandard: {
        supported: true,
        version: "1.0.3"
      }
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Connected to Sui ${NETWORK_CONFIG.current.toUpperCase()}`);
  console.log(`RPC URL: ${getFullnodeUrl(NETWORK_CONFIG.current)}`);
    console.log(`Wallet Standard integration: ENABLED`);
});