// server.js 
// git add . && git commit -m "Smart Contract Tester" && git push origin main
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

const SUI_PACKAGE_ID = process.env.SUI_PACKAGE_ID || '';
const GLOBAL_CONFIG_ID = process.env.GLOBAL_CONFIG_ID || '';
const BINDER_REGISTRY_ID = process.env.BINDER_REGISTRY_ID || '';
const COSMETICS_REGISTRY_ID = process.env.COSMETICS_REGISTRY_ID || '';
const CATALOG_REGISTRY_ID = process.env.CATALOG_REGISTRY_ID || '';
const CARD_REGISTRY_ID = process.env.CARD_REGISTRY_ID || '';
const CLOCK_ID = process.env.CLOCK_ID || '';
const RANDOM_ID = process.env.RANDOM_ID || '';

// Helper to check if contract addresses are set
function requireContractIds(res) {
  if (!SUI_PACKAGE_ID || !GLOBAL_CONFIG_ID || !BINDER_REGISTRY_ID) {
    res.status(500).json({ success: false, error: "Sui contract addresses not configured." });
    return false;
  }
  return true;
}

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
// In server.js, modify the wallet-connect endpoint
app.get("/wallet-connect", (req, res) => {
  // Pass the state parameter to the frontend
  const state = req.query.state;
  res.redirect(`https://sui-frontend-nu.vercel.app/?state=${state}`);
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
      console.warn("Invalid public key format provided, ignoring");
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

    // CRITICAL: Check for existing user profile with proper query
    // This is the main fix for duplicate users
    let { data: existingProfile, error: queryError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("sui_address", walletAddress)
      .maybeSingle(); // Use maybeSingle() instead of single() to avoid errors when no rows found

    if (queryError) {
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
        auth_method: authMethod,
        last_login: new Date().toISOString() // Track last login
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

      // Double-check to prevent race conditions
      const { data: raceCheck } = await supabase
        .from("user_profiles")
        .select("id")
        .eq("sui_address", walletAddress)
        .maybeSingle();

      if (raceCheck) {
        console.log("Race condition detected - user was created by another request");
        finalProfile = raceCheck;
      } else {
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
          updated_at: new Date().toISOString(),
          last_login: new Date().toISOString()
        };

        console.log("Profile data to insert:", JSON.stringify(profileData, null, 2));

        const { data: inserted, error: insertError } = await supabase
          .from("user_profiles")
          .insert([profileData])
          .select()
          .single();

        if (insertError) {
          // Check if it's a unique constraint violation (duplicate)
          if (insertError.code === '23505') {
            console.log("Unique constraint violation - fetching existing user");
            const { data: existing } = await supabase
              .from("user_profiles")
              .select("*")
              .eq("sui_address", walletAddress)
              .single();
            finalProfile = existing;
          } else {
            console.error("Profile insert error:", insertError);
            return res.status(500).json({
              success: false,
              error: "Profile creation failed: " + insertError.message
            });
          }
        } else {
          finalProfile = inserted;
          isNewUser = true;
          console.log("New user profile created:", finalProfile.id);
        }
      }
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
      needsUsernameSetup: requiresUsername,
      timestamp: new Date().toISOString()
    };

    // Store session for Unity polling with expiration
    sessions[state] = {
      ...sessionData,
      expiresAt: Date.now() + (30 * 60 * 1000) // 30 minutes
    };
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

    // CRITICAL: Use proper query with maybeSingle() to prevent duplicate creation
    const { data: existingProfile, error: fetchError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("google_id", userInfo.sub)
      .maybeSingle();

    if (fetchError) {
      console.error("Database query error:", fetchError);
      throw new Error("Database query failed");
    }

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
        email: userInfo.email,
        last_login: new Date().toISOString()
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

      // Double-check to prevent race conditions
      const { data: raceCheck } = await supabase
        .from("user_profiles")
        .select("id")
        .eq("google_id", userInfo.sub)
        .maybeSingle();

      if (raceCheck) {
        console.log("Race condition detected - user was created by another request");
        profile = raceCheck;
      } else {
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
          updated_at: new Date().toISOString(),
          last_login: new Date().toISOString()
        };

        const { data: insertedProfile, error: insertError } = await supabase
          .from("user_profiles")
          .insert([profileData])
          .select()
          .single();

        if (insertError) {
          // Check if it's a unique constraint violation
          if (insertError.code === '23505') {
            console.log("Unique constraint violation - fetching existing user");
            const { data: existing } = await supabase
              .from("user_profiles")
              .select("*")
              .eq("google_id", userInfo.sub)
              .single();
            profile = existing;
          } else {
            console.error("Profile insert error:", insertError);
            throw new Error("Profile creation failed");
          }
        } else {
          profile = insertedProfile;
          isNewUser = true;
        }
      }
    }

    const requiresUsername = needsUsernameSetup(profile.name);

    // Store session with expiration
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
      needsUsernameSetup: requiresUsername,
      timestamp: new Date().toISOString(),
      expiresAt: Date.now() + (30 * 60 * 1000) // 30 minutes
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

        console.log(`Blockchain info:`, blockchainInfo);

      } catch (blockchainError) {
        console.log(`Blockchain check failed: ${blockchainError.message}`);
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


app.post("/create-binder", async (req, res) => {
  if (!requireContractIds(res)) return;

  const { walletAddress, username, displayName } = req.body;
  if (!walletAddress || !username || !displayName) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }

  try {
    console.log(`Creating binder transaction for: ${walletAddress}`);

    // Check if user already has a verified binder
    const { data: existingProfile } = await supabase
      .from("user_profiles")
      .select("active_binder_id, binder_verified")
      .eq("sui_address", walletAddress)
      .single();

    if (existingProfile?.binder_verified && existingProfile?.active_binder_id) {
      return res.status(400).json({
        success: false,
        error: "User already has a verified binder",
        binderId: existingProfile.active_binder_id
      });
    }

    // Construct Move transaction
    const tx = new Transaction();
    tx.moveCall({
      target: `${SUI_PACKAGE_ID}::binder_actions::new`,
      arguments: [
        tx.object(GLOBAL_CONFIG_ID),
        tx.object(COSMETICS_REGISTRY_ID),
        tx.object(BINDER_REGISTRY_ID),
        tx.pure.string(username),
        tx.pure.string(displayName),
      ],
    });

    tx.setSender(walletAddress);

    // FIXED: Increased gas budget significantly
    // Previous: 10000000 (0.01 SUI)
    // New: 50000000 (0.05 SUI) - much safer for complex transactions
    tx.setGasBudget(50000000);

    const serializedTx = tx.serialize();
    console.log("Transaction serialized successfully, length:", serializedTx.length);

    // Create pending binder transaction record
    const { data: userProfile } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (userProfile) {
      await supabase
        .from("binder_transactions")
        .insert({
          user_profile_id: userProfile.id,
          wallet_address: walletAddress,
          display_name: displayName,
          username: username,
          transaction_status: 'pending'
        });
    }

    res.json({
      success: true,
      message: "Binder creation transaction prepared.",
      txBlock: serializedTx,
    });
  } catch (err) {
    console.error("Create binder error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Enhanced card verification endpoint
app.post("/verify-player-inventory", async (req, res) => {
  const { walletAddress, cardObjectIds } = req.body;
  
  try {
    // 1. Get player's binder from database
    const { data: profile } = await supabase
      .from("user_profiles")
      .select("active_binder_id")
      .eq("sui_address", walletAddress)
      .single();
    
    // 2. Verify each card on blockchain
    const verifiedCards = [];
    
    for (const cardId of cardObjectIds) {
      const cardObject = await suiClient.getObject({
        id: cardId,
        options: { showOwner: true, showContent: true }
      });
      
      // 3. Check ownership
      if (cardObject.data?.owner?.ObjectOwner === profile.active_binder_id) {
        verifiedCards.push({
          cardId,
          verified: true,
          owner: profile.active_binder_id
        });
      } else {
        // SECURITY ALERT: Card claimed but not owned!
        await logSecurityIncident({
          walletAddress,
          cardId,
          claimedOwner: profile.active_binder_id,
          actualOwner: cardObject.data?.owner
        });
      }
    }
    
    res.json({
      success: true,
      verifiedCards,
      totalVerified: verifiedCards.length,
      totalClaimed: cardObjectIds.length
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});





app.post("/verify-transaction", async (req, res) => {
  const { transactionHash, walletAddress } = req.body;

  if (!transactionHash || !walletAddress) {
    return res.status(400).json({
      success: false,
      error: "Transaction hash and wallet address are required"
    });
  }

  try {
    console.log(`Verifying transaction: ${transactionHash} for wallet: ${walletAddress}`);

    // Query blockchain for transaction details
    const txResult = await suiClient.getTransactionBlock({
      digest: transactionHash,
      options: {
        showEvents: true,
        showEffects: true,
        showInput: true,
        showObjectChanges: true,
      },
    });

    console.log("Raw transaction result:", JSON.stringify(txResult, null, 2));

    // Check transaction status
    let isSuccess = false;
    let statusInfo = 'unknown';
    const effects = txResult.effects;

    if (effects) {
      if (typeof effects.status === 'string') {
        isSuccess = effects.status.toLowerCase() === 'success';
        statusInfo = effects.status;
      } else if (effects.status && typeof effects.status === 'object') {
        const statusObj = effects.status;
        if ('status' in statusObj && typeof statusObj.status === 'string') {
          isSuccess = statusObj.status.toLowerCase() === 'success';
          statusInfo = statusObj.status;
        } else if ('Success' in statusObj) {
          isSuccess = true;
          statusInfo = 'Success';
        } else if ('Failure' in statusObj) {
          isSuccess = false;
          statusInfo = 'Failure';
        }
      }
    }

    console.log("Transaction status:", { isSuccess, statusInfo });

    if (!isSuccess) {
      return res.json({
        success: true,
        verified: false,
        message: `Transaction found but appears unsuccessful (${statusInfo})`,
        transactionHash: transactionHash
      });
    }

    // === BINDER VERIFICATION ===
    let binderId = null;

    if (effects.created && Array.isArray(effects.created)) {
      console.log(`Checking ${effects.created.length} created objects in effects...`);

      for (let i = 0; i < effects.created.length; i++) {
        const created = effects.created[i];
        const objectId = created?.reference?.objectId;
        const owner = created?.owner;

        if (!objectId) continue;

        console.log(`Created object ${i}:`, {
          objectId: objectId.substring(0, 20) + '...',
          owner: owner
        });

        let isUserOwned = false;
        if (owner && typeof owner === 'object') {
          if (owner.AddressOwner && owner.AddressOwner === walletAddress) {
            isUserOwned = true;
          }
        }

        if (isUserOwned) {
          binderId = objectId;
          console.log(`Found user-owned object (likely binder): ${binderId}`);
          break;
        }
      }

      if (!binderId) {
        for (const created of effects.created) {
          const objectId = created?.reference?.objectId;
          const owner = created?.owner;
          if (objectId && owner && typeof owner === 'object' && 'Shared' in owner) {
            binderId = objectId;
            console.log(`Found shared object (possibly binder): ${binderId}`);
            break;
          }
        }
      }
    }

    if (!binderId && txResult.objectChanges && Array.isArray(txResult.objectChanges)) {
      console.log(`Checking ${txResult.objectChanges.length} object changes as backup...`);
      for (const change of txResult.objectChanges) {
        const changeType = change?.type;
        const objectType = change?.objectType;
        const objectId = change?.objectId;
        if (changeType === 'created' && objectType && objectId) {
          const objectTypeStr = String(objectType).toLowerCase();
          if (objectTypeStr.includes('binder') || (SUI_PACKAGE_ID && objectTypeStr.includes(SUI_PACKAGE_ID.toLowerCase()))) {
            binderId = objectId;
            console.log(`Found binder in objectChanges: ${binderId}`);
            break;
          }
        }
      }
    }

    if (!binderId && effects.created && effects.created.length > 0) {
      console.log("Using fallback: first non-system created object");
      for (const created of effects.created) {
        const objectId = created?.reference?.objectId;
        if (objectId && !objectId.startsWith('0x1') && !objectId.startsWith('0x2')) {
          binderId = objectId;
          console.log(`Fallback binder ID: ${binderId}`);
          break;
        }
      }
    }

    console.log(`Final binder ID determination: ${binderId || 'NOT FOUND'}`);

    // Update binder if found
    if (binderId) {
      try {
        const { data: userProfile } = await supabase
          .from("user_profiles")
          .select("id")
          .eq("sui_address", walletAddress)
          .single();

        if (userProfile) {
          const transactionData = {
            transaction_hash: transactionHash,
            binder_id: binderId,
            transaction_status: 'confirmed',
            blockchain_verified: true,
            updated_at: new Date().toISOString()
          };

          const { data: existingTx } = await supabase
            .from("binder_transactions")
            .select("id")
            .eq('user_profile_id', userProfile.id)
            .eq('wallet_address', walletAddress)
            .eq('transaction_status', 'pending')
            .maybeSingle();

          if (existingTx) {
            await supabase
              .from("binder_transactions")
              .update(transactionData)
              .eq('id', existingTx.id);
          } else {
            await supabase
              .from("binder_transactions")
              .insert({
                user_profile_id: userProfile.id,
                wallet_address: walletAddress,
                ...transactionData,
                created_at: new Date().toISOString()
              });
          }

          await supabase
            .from("user_profiles")
            .update({
              active_binder_id: binderId,
              binder_verified: true,
              binder_transaction_hash: transactionHash,
              last_blockchain_sync: new Date().toISOString(),
              updated_at: new Date().toISOString()
            })
            .eq("id", userProfile.id);

          console.log(`✅ Database updated: Binder ${binderId} verified for user ${walletAddress}`);
        }
      } catch (dbError) {
        console.error("Database update error (binder):", dbError);
      }
    }

    // === BOOSTER PURCHASE VERIFICATION ===
    try {
      // Look for a pending booster purchase with matching wallet and no tx hash yet
      const { data: pendingBooster, error: fetchError } = await supabase
        .from("booster_purchases")
        .select("*")
        .eq("wallet_address", walletAddress)
        .is("transaction_hash", null)
        .eq("purchase_status", "pending")
        .order("purchased_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (pendingBooster) {
        console.log(`Found pending booster purchase for ${walletAddress}, updating with tx hash`);

        // Extract booster pack object ID from created objects
        let boosterPackObjectId = null;
        if (effects.created && Array.isArray(effects.created)) {
          for (const created of effects.created) {
            const objectId = created?.reference?.objectId;
            const owner = created?.owner;

            if (objectId && owner && typeof owner === 'object') {
              // Prefer user-owned or Shared object
              if (
                (owner.AddressOwner && owner.AddressOwner === walletAddress) ||
                ('Shared' in owner)
              ) {
                // Optional: validate it's a booster (if you have a way to distinguish)
                boosterPackObjectId = objectId;
                break;
              }
            }
          }
        }

        // Finalize booster purchase
        const { error: updateError } = await supabase
          .from("booster_purchases")
          .update({
            transaction_hash: transactionHash,
            booster_pack_object_id: boosterPackObjectId,
            purchase_status: 'completed',
            blockchain_verified: true,
            updated_at: new Date().toISOString()
          })
          .eq("id", pendingBooster.id);

        if (updateError) {
          console.error("Failed to update booster purchase record:", updateError);
        } else {
          console.log(`✅ Booster purchase verified: ${boosterPackObjectId || 'NO OBJECT ID'}`);

          // === DEBUG LOG: Check unopened boosters ===
          const { data: unopenedBoosters, error: unopenedError } = await supabase
            .from("booster_purchases")
            .select("booster_pack_serial, booster_pack_object_id, purchased_at")
            .eq("user_profile_id", pendingBooster.user_profile_id)
            .eq("is_opened", false)
            .eq("purchase_status", "completed");

          if (!unopenedError && unopenedBoosters?.length > 0) {
            console.log(`🎮 DEBUG: Player ${walletAddress} has ${unopenedBoosters.length} unopened booster(s):`,
              unopenedBoosters.map(b => ({
                serial: b.booster_pack_serial,
                objectId: b.booster_pack_object_id,
                purchased: b.purchased_at
              }))
            );
          } else {
            console.log(`🎮 DEBUG: Player ${walletAddress} has no unopened boosters.`);
          }
        }
      }
    } catch (boosterErr) {
      console.error("Error during booster verification:", boosterErr);
    }

    // === FINAL RESPONSE ===
    res.json({
      success: true,
      verified: !!binderId,
      binderId: binderId,
      transactionHash: transactionHash,
      statusInfo: statusInfo,
      message: binderId
        ? "Binder creation verified and stored successfully"
        : "Transaction successful but binder ID could not be determined. Please sync binders manually.",
      debugInfo: {
        createdObjectsCount: effects?.created?.length || 0,
        objectChangesCount: txResult.objectChanges?.length || 0,
        firstCreatedObject: effects?.created?.[0]?.reference?.objectId
      }
    });

  } catch (err) {
    console.error("Transaction verification error:", err);
    res.status(500).json({
      success: false,
      verified: false,
      error: "Verification failed: " + (err instanceof Error ? err.message : String(err))
    });
  }
  // === BOOSTER OPENING VERIFICATION ===
  try {
    // Check if this transaction opened a booster
    const { data: unopenedBoosters } = await supabase
      .from("booster_purchases")
      .select("*")
      .eq("wallet_address", walletAddress)
      .eq("is_opened", false)
      .eq("purchase_status", "completed");

    if (unopenedBoosters && unopenedBoosters.length > 0) {
      // Extract card objects created by this transaction
      const cardObjects = [];

      if (effects.created && Array.isArray(effects.created)) {
        for (const created of effects.created) {
          const objectId = created?.reference?.objectId;
          const owner = created?.owner;

          // Cards are owned by ObjectOwner (the binder)
          if (objectId && owner && typeof owner === 'object' && 'ObjectOwner' in owner) {
            // Fetch card details from blockchain
            try {
              const cardObject = await suiClient.getObject({
                id: objectId,
                options: { showContent: true }
              });

              if (cardObject.data?.content?.fields) {
                const fields = cardObject.data.content.fields;
                cardObjects.push({
                  card_object_id: objectId,
                  card_serial: fields.serial || fields.card_serial,
                  card_name: fields.name || fields.card_name,
                  rarity: fields.rarity,
                  card_type: fields.card_type || fields.type,
                  element: fields.element,
                  attack_power: fields.attack || fields.attack_power,
                  defense_power: fields.defense || fields.defense_power,
                  mana_cost: fields.mana_cost || fields.cost
                });
              }
            } catch (err) {
              console.error(`Failed to fetch card ${objectId}:`, err);
            }
          }
        }
      }

      // If we found cards, this was a booster opening
      if (cardObjects.length > 0) {
        console.log(`🎴 Detected ${cardObjects.length} cards opened from booster`);

        // Get user profile
        const { data: userProfile } = await supabase
          .from("user_profiles")
          .select("id")
          .eq("sui_address", walletAddress)
          .single();

        if (userProfile) {
          // Find which booster was opened (match by object ID or use first unopened)
          const openedBooster = unopenedBoosters[0]; // Simplest approach

          // Insert cards into user_cards
          const cardsToInsert = cardObjects.map(card => ({
            user_profile_id: userProfile.id,
            booster_purchase_id: openedBooster.id,
            card_object_id: card.card_object_id,
            card_serial: card.card_serial,
            card_name: card.card_name,
            rarity: card.rarity,
            card_type: card.card_type,
            element: card.element,
            attack_power: card.attack_power,
            defense_power: card.defense_power,
            mana_cost: card.mana_cost,
            obtained_from: 'booster_pack',
            blockchain_verified: true,
            obtained_at: new Date().toISOString()
          }));

          const { error: insertError } = await supabase
            .from("user_cards")
            .insert(cardsToInsert);

          if (insertError) {
            console.error("Failed to insert cards:", insertError);
          } else {
            console.log(`✅ Inserted ${cardObjects.length} cards into user_cards`);

            // Mark booster as opened
            await supabase
              .from("booster_purchases")
              .update({
                is_opened: true,
                opened_at: new Date().toISOString(),
                open_transaction_hash: transactionHash
              })
              .eq("id", openedBooster.id);

            console.log(`✅ Booster ${openedBooster.id} marked as opened`);
          }
        }
      }
    }
  } catch (boosterOpenErr) {
    console.error("Error during booster opening verification:", boosterOpenErr);
  }

});

// Add to server.js
app.get("/user-opened-cards/:transactionHash", async (req, res) => {
  const { transactionHash } = req.params;

  try {
    // Find booster opened by this transaction
    const { data: booster, error: boosterError } = await supabase
      .from("booster_purchases")
      .select("id, user_profile_id")
      .eq("open_transaction_hash", transactionHash)
      .single();

    if (boosterError || !booster) {
      return res.status(404).json({
        success: false,
        error: "No opened booster found"
      });
    }

    // Get cards from this booster
    const { data: cards, error: cardsError } = await supabase
      .from("user_cards")
      .select("*")
      .eq("booster_purchase_id", booster.id)
      .order("obtained_at", { ascending: true });

    if (cardsError) {
      return res.status(500).json({
        success: false,
        error: "Failed to fetch cards"
      });
    }

    res.json({
      success: true,
      cards: cards || [],
      boosterId: booster.id
    });

  } catch (err) {
    console.error("Error fetching opened cards:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});



// Add this to server.js
app.get("/user-unopened-boosters/:walletAddress", async (req, res) => {
  const { walletAddress } = req.params;
  if (!walletAddress || !isValidSuiAddress(walletAddress)) {
    return res.status(400).json({ success: false, error: "Invalid wallet address" });
  }

  try {
    const { data: profile, error: profileError } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (profileError || !profile) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const { data: boosters, error: boostersError } = await supabase
      .from("booster_purchases")
      .select("booster_pack_serial, booster_pack_object_id, purchased_at, id")
      .eq("user_profile_id", profile.id)
      .eq("is_opened", false)
      .eq("purchase_status", "completed")
      .order("purchased_at", { ascending: false });

    if (boostersError) {
      console.error("Error fetching unopened boosters:", boostersError);
      return res.status(500).json({ success: false, error: "Database error" });
    }

    res.json({
      success: true,
      unopenedBoosters: boosters || []
    });
  } catch (err) {
    console.error("Unexpected error in /user-unopened-boosters:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});




app.get("/user-cards/:walletAddress", async (req, res) => {
  const { walletAddress } = req.params;
  
  if (!walletAddress || !isValidSuiAddress(walletAddress)) {
    return res.status(400).json({ 
      success: false, 
      error: "Invalid wallet address" 
    });
  }

  try {
    console.log(`Fetching cards for wallet: ${walletAddress}`);

    // Get user profile
    const { data: profile, error: profileError } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();
    
    if (profileError || !profile) {
      return res.status(404).json({ 
        success: false, 
        error: "User profile not found" 
      });
    }

    // Get all cards for this user
    const { data: cards, error: cardsError } = await supabase
      .from("user_cards")
      .select("*")
      .eq("user_profile_id", profile.id)
      .order("obtained_at", { ascending: false });
    
    if (cardsError) {
      console.error("Error fetching cards:", cardsError);
      return res.status(500).json({ 
        success: false, 
        error: "Failed to fetch cards" 
      });
    }

    console.log(`✅ Found ${cards?.length || 0} cards for user ${profile.id}`);

    res.json({
      success: true,
      cards: cards || [],
      totalCards: cards?.length || 0
    });

  } catch (err) {
    console.error("User cards fetch error:", err);
    res.status(500).json({ 
      success: false, 
      error: err.message 
    });
  }
});






// Add this debug endpoint to your server.js to see the raw transaction data

app.post("/debug-transaction", async (req, res) => {
  const { transactionHash } = req.body;

  if (!transactionHash) {
    return res.status(400).json({
      success: false,
      error: "Transaction hash is required"
    });
  }

  try {
    console.log(`Debugging transaction: ${transactionHash}`);

    // Query blockchain for transaction details
    const txResult = await suiClient.getTransactionBlock({
      digest: transactionHash,
      options: {
        showEvents: true,
        showEffects: true,
        showInput: true,
        showObjectChanges: true,
      },
    });

    // Return the full transaction data for debugging
    res.json({
      success: true,
      transactionHash: transactionHash,
      fullTransaction: txResult,
      statusAnalysis: {
        hasEffects: !!txResult.effects,
        hasStatus: !!txResult.effects?.status,
        statusValue: txResult.effects?.status,
        statusType: typeof txResult.effects?.status,
        objectChangesCount: txResult.objectChanges?.length || 0,
        eventsCount: txResult.events?.length || 0
      }
    });

  } catch (err) {
    console.error("Transaction debug error:", err);
    res.status(500).json({
      success: false,
      error: "Debug failed: " + err.message
    });
  }
});

app.get("/user-binder-status/:walletAddress", async (req, res) => {
  const { walletAddress } = req.params;

  if (!walletAddress || !isValidSuiAddress(walletAddress)) {
    return res.status(400).json({
      success: false,
      error: "Invalid wallet address"
    });
  }

  try {
    // Query user profile for binder info
    const { data: userProfile, error } = await supabase
      .from("user_profiles")
      .select(`
        active_binder_id,
        binder_verified,
        binder_created_at,
        binder_transaction_hash,
        last_blockchain_sync
      `)
      .eq("sui_address", walletAddress)
      .single();

    if (error && error.code !== 'PGRST116') { // Not found is OK
      throw error;
    }

    let hasBinder = false;
    let binderInfo = null;
    let needsVerification = false;

    if (userProfile?.binder_verified && userProfile?.active_binder_id) {
      // User has verified binder
      hasBinder = true;
      binderInfo = {
        binderId: userProfile.active_binder_id,
        verified: true,
        createdAt: userProfile.binder_created_at,
        transactionHash: userProfile.binder_transaction_hash
      };
    } else {
      // Check for pending transactions
      const { data: pendingTransactions } = await supabase
        .from("binder_transactions")
        .select("*")
        .eq("wallet_address", walletAddress)
        .in("transaction_status", ["pending", "confirmed"])
        .order("created_at", { ascending: false })
        .limit(1);

      if (pendingTransactions && pendingTransactions.length > 0) {
        const pending = pendingTransactions[0];
        needsVerification = pending.transaction_status === 'pending';
        binderInfo = {
          binderId: pending.binder_id,
          verified: pending.blockchain_verified,
          status: pending.transaction_status,
          createdAt: pending.created_at,
          transactionHash: pending.transaction_hash,
          needsVerification
        };
      }
    }

    // Optional: Query blockchain directly for double-verification
    let blockchainBinders = [];
    if (hasBinder && userProfile.active_binder_id) {
      try {
        const binderObject = await suiClient.getObject({
          id: userProfile.active_binder_id,
          options: { showContent: true, showOwner: true }
        });

        if (binderObject.data && binderObject.data.owner) {
          const ownerAddress = typeof binderObject.data.owner === 'object'
            ? binderObject.data.owner.AddressOwner
            : binderObject.data.owner;

          if (ownerAddress === walletAddress) {
            blockchainBinders.push({
              id: userProfile.active_binder_id,
              verified: true,
              onChain: true
            });
          }
        }
      } catch (blockchainError) {
        console.log(`Could not verify binder on blockchain: ${blockchainError.message}`);
      }
    }

    res.json({
      success: true,
      hasBinder,
      binderInfo,
      needsVerification,
      blockchainBinders,
      walletAddress
    });

  } catch (err) {
    console.error("Binder status check error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to check binder status: " + err.message
    });
  }
});

app.post("/sync-user-binders", async (req, res) => {
  const { walletAddress } = req.body;

  if (!walletAddress || !isValidSuiAddress(walletAddress)) {
    return res.status(400).json({
      success: false,
      error: "Invalid wallet address"
    });
  }

  try {
    console.log(`Syncing binders for wallet: ${walletAddress}`);

    // Query user's objects for binders
    const ownedObjects = await suiClient.getOwnedObjects({
      owner: walletAddress,
      filter: {
        StructType: `${SUI_PACKAGE_ID}::binder::Binder`
      },
      options: {
        showContent: true,
        showType: true
      }
    });

    const binders = ownedObjects.data.filter(obj => obj.data && obj.data.content);

    if (binders.length === 0) {
      return res.json({
        success: true,
        message: "No binders found on blockchain",
        binders: []
      });
    }

    // Get user profile
    const { data: userProfile } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (userProfile && binders.length > 0) {
      const primaryBinder = binders[0]; // Use first binder as primary

      // Update user profile with synced binder
      await supabase
        .from("user_profiles")
        .update({
          active_binder_id: primaryBinder.data.objectId,
          binder_verified: true,
          last_blockchain_sync: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq("id", userProfile.id);

      console.log(`Synced binder: ${primaryBinder.data.objectId} for user: ${walletAddress}`);
    }

    res.json({
      success: true,
      message: `Found and synced ${binders.length} binder(s)`,
      binders: binders.map(b => ({
        id: b.data.objectId,
        type: b.data.type,
        content: b.data.content
      }))
    });

  } catch (err) {
    console.error("Binder sync error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to sync binders: " + err.message
    });
  }
});

// Add these endpoints to your server.js

// Update user profile image
app.post("/update-profile-image", async (req, res) => {
  const { walletAddress, profileImageId } = req.body;

  if (!walletAddress || !profileImageId) {
    return res.status(400).json({
      success: false,
      error: "Wallet address and profile image ID are required"
    });
  }

  try {
    // Validate wallet address
    if (!isValidSuiAddress(walletAddress)) {
      return res.status(400).json({
        success: false,
        error: "Invalid Sui address format"
      });
    }

    // Update profile image in database
    const { data: updatedProfile, error: updateError } = await supabase
      .from("user_profiles")
      .update({
        profile_image_id: profileImageId,
        updated_at: new Date().toISOString()
      })
      .eq("sui_address", walletAddress)
      .select()
      .single();

    if (updateError) {
      console.error("Profile image update error:", updateError);
      return res.status(500).json({
        success: false,
        error: "Failed to update profile image"
      });
    }

    console.log(`Profile image updated: ${walletAddress} -> ${profileImageId}`);

    res.json({
      success: true,
      message: "Profile image updated successfully",
      profileImageId: profileImageId
    });

  } catch (err) {
    console.error("Profile image update error:", err);
    res.status(500).json({
      success: false,
      error: "Profile image update failed: " + err.message
    });
  }
});

// Get user profile image
app.get("/get-profile-image/:walletAddress", async (req, res) => {
  const { walletAddress } = req.params;

  if (!walletAddress || !isValidSuiAddress(walletAddress)) {
    return res.status(400).json({
      success: false,
      error: "Invalid wallet address"
    });
  }

  try {
    const { data: profile, error } = await supabase
      .from("user_profiles")
      .select("profile_image_id")
      .eq("sui_address", walletAddress)
      .single();

    if (error) {
      console.error("Profile image fetch error:", error);
      return res.status(404).json({
        success: false,
        error: "Profile not found"
      });
    }

    res.json({
      success: true,
      profileImageId: profile.profile_image_id || "profile_1" // Default
    });

  } catch (err) {
    console.error("Profile image fetch error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to fetch profile image: " + err.message
    });
  }
});


// app.post("/buy-booster", async (req, res) => {
//   if (!requireContractIds(res)) return;

//   const { walletAddress, binderId, boosterPackSerial, price, coinType } = req.body;
//   if (!walletAddress || !binderId || !boosterPackSerial || !price || !coinType) {
//     return res.status(400).json({ success: false, error: "Missing required fields." });
//   }

//   try {
//     console.log(`Creating buy booster transaction for: ${walletAddress}`);

//     const tx = new Transaction();

//     // Split coin for payment
//     const [paymentCoin] = tx.splitCoins(tx.gas, [tx.pure.u64(price)]);

//     tx.moveCall({
//       target: `${SUI_PACKAGE_ID}::booster::buy_booster_pack`,
//       typeArguments: [coinType],
//       arguments: [
//         tx.object(GLOBAL_CONFIG_ID),
//         tx.object(CATALOG_REGISTRY_ID),
//         tx.object(binderId),
//         tx.pure.string(boosterPackSerial),
//         paymentCoin,
//         tx.object(CLOCK_ID),
//       ],
//     });

//     tx.setSender(walletAddress);

//     // FIXED: Increased from 15000000 to 80000000 (0.08 SUI)
//     // Buy booster needs more gas due to coin splitting
//     tx.setGasBudget(80000000);

//     const serializedTx = tx.serialize();
//     console.log("Buy booster transaction serialized successfully");

//     res.json({
//       success: true,
//       message: "Booster pack purchase transaction prepared.",
//       txBlock: serializedTx,
//     });
//   } catch (err) {
//     console.error("Buy booster error:", err);
//     res.status(500).json({ success: false, error: err.message });
//   }
// });


app.post("/buy-booster", async (req, res) => {
  if (!requireContractIds(res)) return;
  const { walletAddress, binderId, boosterPackSerial, price, coinType } = req.body;
  if (!walletAddress || !binderId || !boosterPackSerial || !price || !coinType) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }

  try {
    console.log(`Creating buy booster transaction for: ${walletAddress}`);

    // 🔍 Fetch user profile to get user_profile_id
    const { data: userProfile, error: profileError } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (profileError || !userProfile) {
      console.error("User profile not found for wallet:", walletAddress);
      return res.status(404).json({ success: false, error: "User profile not found." });
    }

    // 📥 Insert PENDING booster purchase record BEFORE sending tx
    const { data: boosterRecord, error: insertError } = await supabase
      .from("booster_purchases")
      .insert({
        user_profile_id: userProfile.id,
        wallet_address: walletAddress,
        binder_id: binderId,
        booster_pack_serial: boosterPackSerial,
        price_paid: price.toString(),
        coin_type: coinType,
        purchase_status: 'pending',
        purchased_at: new Date().toISOString()
      })
      .select()
      .single();

    if (insertError) {
      console.error("Failed to create booster purchase record:", insertError);
      return res.status(500).json({ success: false, error: "Failed to log booster purchase." });
    }

    console.log(`✅ Pending booster purchase logged (ID: ${boosterRecord.id})`);

    // 💸 Build transaction
    const tx = new Transaction();
    const [paymentCoin] = tx.splitCoins(tx.gas, [tx.pure.u64(price)]);
    tx.moveCall({
      target: `${SUI_PACKAGE_ID}::booster::buy_booster_pack`,
      typeArguments: [coinType],
      arguments: [
        tx.object(GLOBAL_CONFIG_ID),
        tx.object(CATALOG_REGISTRY_ID),
        tx.object(binderId),
        tx.pure.string(boosterPackSerial),
        paymentCoin,
        tx.object(CLOCK_ID),
      ],
    });
    tx.setSender(walletAddress);
    tx.setGasBudget(80000000);
    const serializedTx = tx.serialize();

    console.log("Buy booster transaction prepared successfully");

    res.json({
      success: true,
      message: "Booster pack purchase transaction prepared.",
      txBlock: serializedTx,
      boosterPurchaseId: boosterRecord.id // Optional: useful for frontend correlation
    });

  } catch (err) {
    console.error("Buy booster error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});


// Replace your entire /open-booster endpoint with this version

app.post("/open-booster", async (req, res) => {
  console.log("🎴 === OPEN BOOSTER REQUEST RECEIVED ===");
  
  try {
    // 1. Validate required contract IDs
    if (!SUI_PACKAGE_ID || !GLOBAL_CONFIG_ID || !CATALOG_REGISTRY_ID || 
        !CARD_REGISTRY_ID) {
      console.error("❌ Contract addresses not configured");
      return res.status(500).json({ 
        success: false, 
        error: "Sui contract addresses not configured." 
      });
    }

    const { walletAddress, binderId, boosterPackSerial } = req.body;
    
    console.log("📦 Request parameters:", {
      walletAddress: walletAddress?.substring(0, 20) + "...",
      binderId: binderId?.substring(0, 20) + "...",
      boosterPackSerial
    });

    // 2. Validate request body
    if (!walletAddress || !binderId || !boosterPackSerial) {
      console.error("❌ Missing required fields");
      return res.status(400).json({ 
        success: false, 
        error: "Missing required fields: walletAddress, binderId, or boosterPackSerial" 
      });
    }

    // 3. Get user profile
    console.log("🔍 Looking up user profile...");
    const { data: userProfile, error: profileError } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .maybeSingle();

    if (profileError) {
      console.error("❌ Database error fetching user profile:", profileError);
      return res.status(500).json({
        success: false,
        error: "Database error: " + profileError.message
      });
    }

    if (!userProfile) {
      console.error("❌ User profile not found");
      return res.status(404).json({
        success: false,
        error: "User profile not found"
      });
    }

    console.log("✅ User profile found:", userProfile.id);

    // 4. Get the unopened booster pack
    console.log("🔍 Looking for unopened booster...");
    const { data: boosterPack, error: boosterError } = await supabase
      .from("booster_purchases")
      .select("*")
      .eq("user_profile_id", userProfile.id)
      .eq("booster_pack_serial", boosterPackSerial)
      .eq("is_opened", false)
      .eq("purchase_status", "completed")
      .order("purchased_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    if (boosterError) {
      console.error("❌ Database error fetching booster:", boosterError);
      return res.status(500).json({
        success: false,
        error: "Database error: " + boosterError.message
      });
    }

    if (!boosterPack) {
      console.error("❌ No unopened booster found");
      return res.status(404).json({
        success: false,
        error: "No unopened booster pack found with this serial. Please purchase a booster first."
      });
    }

    console.log("✅ Found unopened booster:", {
      id: boosterPack.id,
      serial: boosterPackSerial,
      purchasedAt: boosterPack.purchased_at
    });

    // 5. Build transaction - CORRECTLY THIS TIME
    console.log("🔨 Building open booster transaction...");
    
    const tx = new Transaction();

    try {
      // ✅ CRITICAL FIX: Use tx.object.random() and tx.object.clock()
      tx.moveCall({
        target: `${SUI_PACKAGE_ID}::booster::open_booster`,
        arguments: [
          tx.object(GLOBAL_CONFIG_ID),          // arg 0: &GlobalConfig
          tx.object(CATALOG_REGISTRY_ID),       // arg 1: &CatalogRegistry  
          tx.object(CARD_REGISTRY_ID),          // arg 2: &mut CardRegistry
          tx.object(binderId),                  // arg 3: &mut Binder
          tx.pure.string(boosterPackSerial),    // arg 4: String (pack serial)
          tx.object.random(),                   // arg 5: &Random ⬅️ SPECIAL SYNTAX
          tx.object.clock(),                    // arg 6: &Clock ⬅️ SPECIAL SYNTAX
        ],
      });

      tx.setSender(walletAddress);
      
      // Increased gas for card minting operations
      tx.setGasBudget(150000000); // 0.15 SUI

      console.log("✅ Transaction built successfully");
      console.log("📋 Transaction details:", {
        sender: walletAddress.substring(0, 20) + "...",
        gasBudget: "150000000 (0.15 SUI)",
        target: `${SUI_PACKAGE_ID}::booster::open_booster`,
        packSerial: boosterPackSerial,
        binderId: binderId.substring(0, 20) + "...",
        usesRandomAndClockSystemObjects: true
      });

    } catch (txBuildError) {
      console.error("❌ Transaction build error:", txBuildError);
      return res.status(500).json({
        success: false,
        error: `Failed to build transaction: ${txBuildError.message}`
      });
    }

    // 6. Serialize transaction
    let serializedTx;
    try {
      serializedTx = tx.serialize();
      console.log(`✅ Transaction serialized: ${serializedTx.length} bytes`);
    } catch (serializeError) {
      console.error("❌ Transaction serialization error:", serializeError);
      return res.status(500).json({
        success: false,
        error: `Failed to serialize transaction: ${serializeError.message}`
      });
    }

    // 7. Update database status
    console.log("💾 Updating database status...");
    try {
      await supabase
        .from("booster_purchases")
        .update({
          purchase_status: 'opening',
          updated_at: new Date().toISOString()
        })
        .eq("id", boosterPack.id);

      console.log(`✅ Booster ${boosterPack.id} marked as 'opening'`);
    } catch (dbUpdateError) {
      console.warn("⚠️ Database update warning:", dbUpdateError.message);
    }

    // 8. Return success response
    console.log("✅ === OPEN BOOSTER REQUEST COMPLETE ===");
    
    res.json({
      success: true,
      message: "Open booster transaction prepared successfully",
      txBlock: serializedTx,
      boosterPackId: boosterPack.id,
      boosterPackSerial: boosterPackSerial,
      debug: {
        walletAddress: walletAddress.substring(0, 20) + "...",
        binderId: binderId.substring(0, 20) + "...",
        boosterPackSerial,
        gasBudget: "0.15 SUI",
        usesSystemObjects: true
      }
    });

  } catch (err) {
    console.error("❌ === CRITICAL ERROR IN OPEN BOOSTER ===");
    console.error("Error type:", err.constructor.name);
    console.error("Error message:", err.message);
    console.error("Error stack:", err.stack);
    
    res.status(500).json({ 
      success: false, 
      error: `Server error: ${err.message}`,
      errorType: err.constructor.name
    });
  }
});


// Add this debug endpoint
app.post("/verify-binder-ownership", async (req, res) => {
  const { walletAddress, binderId } = req.body;
  
  try {
    console.log(`🔍 Verifying binder ${binderId} for ${walletAddress}`);
    
    // Fetch the binder object from blockchain
    const binderObject = await suiClient.getObject({
      id: binderId,
      options: { 
        showOwner: true, 
        showType: true,
        showContent: true 
      }
    });
    
    if (!binderObject.data) {
      return res.json({
        success: false,
        error: "Binder not found on blockchain",
        binderId
      });
    }
    
    // Check ownership
    const owner = binderObject.data.owner;
    let isOwnedByUser = false;
    
    if (owner && typeof owner === 'object') {
      if (owner.AddressOwner === walletAddress) {
        isOwnedByUser = true;
      }
    }
    
    // Check if it's actually a Binder type
    const objectType = binderObject.data.type;
    const isBinderType = objectType && objectType.includes('::binder::Binder');
    
    console.log("Binder verification:", {
      exists: true,
      isOwnedByUser,
      isBinderType,
      objectType,
      owner
    });
    
    res.json({
      success: true,
      binderId,
      exists: true,
      isOwnedByUser,
      isCorrectType: isBinderType,
      objectType,
      owner,
      canOpenBooster: isOwnedByUser && isBinderType
    });
    
  } catch (err) {
    console.error("Binder verification error:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});





// Debug endpoints remain the same
app.get("/debug-booster/:walletAddress/:boosterSerial", async (req, res) => {
  const { walletAddress, boosterSerial } = req.params;

  try {
    const { data: userProfile } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (!userProfile) {
      return res.status(404).json({ error: "User not found" });
    }

    const { data: boosters } = await supabase
      .from("booster_purchases")
      .select("*")
      .eq("user_profile_id", userProfile.id)
      .eq("booster_pack_serial", boosterSerial)
      .order("purchased_at", { ascending: false });

    const boostersWithBlockchainStatus = await Promise.all(
      (boosters || []).map(async (booster) => {
        let blockchainStatus = "N/A";
        let objectDetails = null;
        
        if (booster.booster_pack_object_id) {
          try {
            const obj = await suiClient.getObject({
              id: booster.booster_pack_object_id,
              options: { 
                showOwner: true, 
                showType: true,
                showContent: true
              }
            });
            
            if (obj.data) {
              blockchainStatus = "EXISTS";
              objectDetails = {
                objectId: obj.data.objectId,
                type: obj.data.type,
                owner: obj.data.owner,
                content: obj.data.content
              };
            } else {
              blockchainStatus = "NOT_FOUND";
            }
          } catch (e) {
            blockchainStatus = `ERROR: ${e.message}`;
          }
        } else {
          blockchainStatus = "NO_OBJECT_ID";
        }

        return {
          ...booster,
          blockchainStatus,
          objectDetails
        };
      })
    );

    res.json({
      success: true,
      boosters: boostersWithBlockchainStatus
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/inspect-object/:objectId", async (req, res) => {
  const { objectId } = req.params;

  try {
    console.log(`🔍 Inspecting object: ${objectId}`);

    const obj = await suiClient.getObject({
      id: objectId,
      options: {
        showOwner: true,
        showType: true,
        showContent: true,
        showDisplay: true,
        showPreviousTransaction: true
      }
    });

    if (!obj.data) {
      return res.status(404).json({
        success: false,
        error: "Object not found on blockchain"
      });
    }

    res.json({
      success: true,
      object: obj.data,
      rawResponse: obj
    });

  } catch (err) {
    console.error("Object inspection error:", err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.get("/inspect-object/:objectId", async (req, res) => {
  const { objectId } = req.params;

  try {
    console.log(`🔍 Inspecting object: ${objectId}`);

    const obj = await suiClient.getObject({
      id: objectId,
      options: {
        showOwner: true,
        showType: true,
        showContent: true,
        showDisplay: true,
        showPreviousTransaction: true
      }
    });

    if (!obj.data) {
      return res.status(404).json({
        success: false,
        error: "Object not found on blockchain"
      });
    }

    res.json({
      success: true,
      object: obj.data,
      rawResponse: obj
    });

  } catch (err) {
    console.error("Object inspection error:", err);
    res.status(500).json({
      success: false,
      error: err.message
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










//////////
//////

///////

// Replace your server /verify-transaction endpoint with this properly typed version

// app.post("/verify-transaction", async (req, res) => {
//   const { transactionHash, walletAddress } = req.body;

//   if (!transactionHash || !walletAddress) {
//     return res.status(400).json({
//       success: false,
//       error: "Transaction hash and wallet address are required"
//     });
//   }

//   try {
//     console.log(`Verifying transaction: ${transactionHash} for wallet: ${walletAddress}`);

//     // Query blockchain for transaction details
//     const txResult = await suiClient.getTransactionBlock({
//       digest: transactionHash,
//       options: {
//         showEvents: true,
//         showEffects: true,
//         showInput: true,
//         showObjectChanges: true,
//       },
//     });

//     console.log("Raw transaction result:", JSON.stringify(txResult, null, 2));

//     // Check transaction status
//     let isSuccess = false;
//     let statusInfo = 'unknown';
//     const effects = txResult.effects;

//     if (effects) {
//       // Check status
//       if (typeof effects.status === 'string') {
//         isSuccess = effects.status.toLowerCase() === 'success';
//         statusInfo = effects.status;
//       } else if (effects.status && typeof effects.status === 'object') {
//         const statusObj = effects.status;
//         if ('status' in statusObj && typeof statusObj.status === 'string') {
//           isSuccess = statusObj.status.toLowerCase() === 'success';
//           statusInfo = statusObj.status;
//         } else if ('Success' in statusObj) {
//           isSuccess = true;
//           statusInfo = 'Success';
//         } else if ('Failure' in statusObj) {
//           isSuccess = false;
//           statusInfo = 'Failure';
//         }
//       }
//     }

//     console.log("Transaction status:", { isSuccess, statusInfo });
//     // === END BOOSTER VERIFICATION BLOCK ===

//     if (!isSuccess) {
//       return res.json({
//         success: true,
//         verified: false,
//         message: `Transaction found but appears unsuccessful (${statusInfo})`,
//         transactionHash: transactionHash
//       });
//     }

//     // FIXED: Look for binder ID in effects.created array (where it actually is)
//     let binderId = null;

//     // First, check effects.created (this is where your binder actually is)
//     if (effects.created && Array.isArray(effects.created)) {
//       console.log(`Checking ${effects.created.length} created objects in effects...`);

//       for (let i = 0; i < effects.created.length; i++) {
//         const created = effects.created[i];
//         const objectId = created?.reference?.objectId;
//         const owner = created?.owner;

//         if (!objectId) continue;

//         console.log(`Created object ${i}:`, {
//           objectId: objectId.substring(0, 20) + '...',
//           owner: owner
//         });

//         // Check if this object is owned by the user (not shared, not ObjectOwner of another address)
//         let isUserOwned = false;

//         if (owner && typeof owner === 'object') {
//           // Check for AddressOwner
//           if (owner.AddressOwner && owner.AddressOwner === walletAddress) {
//             isUserOwned = true;
//           }
//           // ObjectOwner means it's owned by another object (like a table)
//           // Shared means it's a shared object
//           // We want objects directly owned by the user
//         }

//         // If owned by user, this is likely the binder
//         if (isUserOwned) {
//           binderId = objectId;
//           console.log(`Found user-owned object (likely binder): ${binderId}`);
//           break;
//         }
//       }

//       // Fallback: If we didn't find a user-owned object, look for Shared objects
//       // (In case your binder is created as a shared object)
//       if (!binderId) {
//         for (const created of effects.created) {
//           const objectId = created?.reference?.objectId;
//           const owner = created?.owner;

//           if (objectId && owner && typeof owner === 'object' && 'Shared' in owner) {
//             binderId = objectId;
//             console.log(`Found shared object (possibly binder): ${binderId}`);
//             break;
//           }
//         }
//       }
//     }

//     // Also check objectChanges as backup (even though it's empty in your case)
//     if (!binderId && txResult.objectChanges && Array.isArray(txResult.objectChanges)) {
//       console.log(`Checking ${txResult.objectChanges.length} object changes as backup...`);

//       for (const change of txResult.objectChanges) {
//         const changeType = change && typeof change === 'object' ? change.type : null;
//         const objectType = change && typeof change === 'object' ? change.objectType : null;
//         const objectId = change && typeof change === 'object' ? change.objectId : null;

//         if (changeType === 'created' && objectType && objectId) {
//           const objectTypeStr = String(objectType).toLowerCase();

//           if (objectTypeStr.includes('binder') ||
//             (SUI_PACKAGE_ID && objectTypeStr.includes(SUI_PACKAGE_ID.toLowerCase()))) {
//             binderId = objectId;
//             console.log(`Found binder in objectChanges: ${binderId}`);
//             break;
//           }
//         }
//       }
//     }

//     // Fallback: Use first created object that's not a coin
//     if (!binderId && effects.created && effects.created.length > 0) {
//       console.log("Using fallback: first non-system created object");

//       for (const created of effects.created) {
//         const objectId = created?.reference?.objectId;

//         // Skip system objects (those starting with 0x1, 0x2, etc. for system packages)
//         if (objectId && !objectId.startsWith('0x1') && !objectId.startsWith('0x2')) {
//           binderId = objectId;
//           console.log(`Fallback binder ID: ${binderId}`);
//           break;
//         }
//       }
//     }

//     console.log(`Final binder ID determination: ${binderId || 'NOT FOUND'}`);

//     // Update database if we found a binder
//     if (binderId) {
//       try {
//         const { data: userProfile } = await supabase
//           .from("user_profiles")
//           .select("id")
//           .eq("sui_address", walletAddress)
//           .single();

//         if (userProfile) {
//           // Update or create transaction record
//           const transactionData = {
//             transaction_hash: transactionHash,
//             binder_id: binderId,
//             transaction_status: 'confirmed',
//             blockchain_verified: true,
//             updated_at: new Date().toISOString()
//           };

//           const { data: existingTx } = await supabase
//             .from("binder_transactions")
//             .select("id")
//             .eq('user_profile_id', userProfile.id)
//             .eq('wallet_address', walletAddress)
//             .eq('transaction_status', 'pending')
//             .maybeSingle();

//           if (existingTx) {
//             await supabase
//               .from("binder_transactions")
//               .update(transactionData)
//               .eq('id', existingTx.id);
//           } else {
//             await supabase
//               .from("binder_transactions")
//               .insert({
//                 user_profile_id: userProfile.id,
//                 wallet_address: walletAddress,
//                 ...transactionData,
//                 created_at: new Date().toISOString()
//               });
//           }

//           // Update user profile
//           await supabase
//             .from("user_profiles")
//             .update({
//               active_binder_id: binderId,
//               binder_verified: true,
//               binder_transaction_hash: transactionHash,
//               last_blockchain_sync: new Date().toISOString(),
//               updated_at: new Date().toISOString()
//             })
//             .eq("id", userProfile.id);

//           console.log(`✅ Database updated: Binder ${binderId} verified for user ${walletAddress}`);
//         }
//       } catch (dbError) {
//         console.error("Database update error:", dbError);
//         // Don't fail the whole request due to database issues
//       }
//     }

//     res.json({
//       success: true,
//       verified: !!binderId,
//       binderId: binderId,
//       transactionHash: transactionHash,
//       statusInfo: statusInfo,
//       message: binderId
//         ? "Binder creation verified and stored successfully"
//         : "Transaction successful but binder ID could not be determined. Please sync binders manually.",
//       debugInfo: {
//         createdObjectsCount: effects?.created?.length || 0,
//         objectChangesCount: txResult.objectChanges?.length || 0,
//         firstCreatedObject: effects?.created?.[0]?.reference?.objectId
//       }
//     });

//   } catch (err) {
//     console.error("Transaction verification error:", err);
//     res.status(500).json({
//       success: false,
//       verified: false,
//       error: "Verification failed: " + (err instanceof Error ? err.message : String(err))
//     });
//   }
// });


// Server endpoint to get user's cards
// app.get("/user-cards/:walletAddress", async (req, res) => {
//   const { walletAddress } = req.params;
  
//   const { data: profile } = await supabase
//     .from("user_profiles")
//     .select("id")
//     .eq("sui_address", walletAddress)
//     .single();
    
//   const { data: cards } = await supabase
//     .from("user_cards")
//     .select("*")
//     .eq("user_profile_id", profile.id)
//     .order("obtained_at", { ascending: false });
    
//   res.json({ success: true, cards });
// });
