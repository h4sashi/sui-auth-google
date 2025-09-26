// server.js - Refactored with external HTML template
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

// app.post("/create-binder", async (req, res) => {
//   if (!requireContractIds(res)) return;

//   const { walletAddress, username, displayName } = req.body;
//   if (!walletAddress || !username || !displayName) {
//     return res.status(400).json({ success: false, error: "Missing required fields." });
//   }

//   try {
//     console.log(`Creating binder transaction for: ${walletAddress}`);

//     // Construct Move transaction
//     const tx = new Transaction();
//     tx.moveCall({
//       target: `${SUI_PACKAGE_ID}::binder_actions::new`,
//       arguments: [
//         tx.object(GLOBAL_CONFIG_ID),
//         tx.object(COSMETICS_REGISTRY_ID),
//         tx.object(BINDER_REGISTRY_ID),
//         tx.pure.string(username),
//         tx.pure.string(displayName),
//       ],
//     });

//     // Set gas budget and sender - FIXED: Use setGasBudget instead of setGasLimit
//     tx.setSender(walletAddress);
//     tx.setGasBudget(10000000); // 0.01 SUI

//     // Serialize the transaction properly
//     const serializedTx = tx.serialize();
//     console.log("Transaction serialized successfully, length:", serializedTx.length);

//     res.json({
//       success: true,
//       message: "Binder creation transaction prepared.",
//       txBlock: serializedTx, // This is now a proper base64 string
//     });
//   } catch (err) {
//     console.error("Create binder error:", err);
//     res.status(500).json({ success: false, error: err.message });
//   }
// });

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
    tx.setGasBudget(10000000);

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

    console.log("Transaction effects status:", txResult.effects?.status?.status);
    console.log("Object changes:", txResult.objectChanges?.length || 0);
    console.log("Events:", txResult.events?.length || 0);

    // Check transaction status - handle both string and object formats
    const txStatus = txResult.effects?.status?.status || txResult.effects?.status;
    const isSuccess = txStatus === 'success' || txStatus === 'Success' ||
      (typeof txStatus === 'object' && txStatus.status === 'success');

    console.log("Transaction status object:", JSON.stringify(txResult.effects?.status, null, 2));
    console.log("Is transaction successful:", isSuccess);

    if (!isSuccess) {
      return res.json({
        success: false,
        verified: false,
        message: "Transaction failed on blockchain",
        txStatus: txStatus,
        fullStatus: txResult.effects?.status
      });
    }

    let binderId = null;

    // Method 1: Look for created objects first (most reliable)
    if (txResult.objectChanges) {
      console.log("Checking object changes for binder creation...");

      for (const change of txResult.objectChanges) {
        console.log(`Object change type: ${change.type}, objectType: ${change.objectType}`);

        if (change.type === 'created' && change.objectType) {
          // Look for binder objects - check various possible type names
          if (change.objectType.includes('::binder::Binder') ||
            change.objectType.includes('::Binder') ||
            change.objectType.includes('binder')) {
            binderId = change.objectId;
            console.log(`Found binder from object changes: ${binderId}`);
            break;
          }
        }
      }
    }

    // Method 2: Look for events if object changes didn't work
    if (!binderId && txResult.events) {
      console.log("Checking events for binder creation...");

      for (const event of txResult.events) {
        console.log(`Event type: ${event.type}`);

        if (event.type.includes('binder') ||
          event.type.includes('Binder') ||
          event.type.includes('BinderCreated')) {

          if (event.parsedJson) {
            // Try different possible field names
            binderId = event.parsedJson.binder_id ||
              event.parsedJson.id ||
              event.parsedJson.object_id ||
              event.parsedJson.binderId;

            if (binderId) {
              console.log(`Found binder from events: ${binderId}`);
              break;
            }
          }
        }
      }
    }

    // Method 3: If still no binder found, look for any created object (fallback)
    if (!binderId && txResult.objectChanges) {
      console.log("Using fallback: looking for any created object...");

      const createdObjects = txResult.objectChanges.filter(change => change.type === 'created');
      if (createdObjects.length > 0) {
        // Use the first created object (excluding gas coin)
        for (const obj of createdObjects) {
          if (!obj.objectType.includes('::coin::Coin')) {
            binderId = obj.objectId;
            console.log(`Found created object (fallback): ${binderId}`);
            break;
          }
        }
      }
    }

    if (!binderId) {
      console.log("Could not extract binder ID from transaction");
      console.log("Full transaction result:", JSON.stringify(txResult, null, 2));

      return res.json({
        success: false,
        verified: false,
        message: "Could not extract binder ID from transaction, but transaction succeeded",
        txStatus: "success",
        debugInfo: {
          objectChanges: txResult.objectChanges?.length || 0,
          events: txResult.events?.length || 0,
          transactionHash
        }
      });
    }

    // Update database with verified transaction
    const { data: userProfile } = await supabase
      .from("user_profiles")
      .select("id")
      .eq("sui_address", walletAddress)
      .single();

    if (userProfile) {
      // Update or insert binder transaction record
      const { data: existingTx } = await supabase
        .from("binder_transactions")
        .select("id")
        .eq('user_profile_id', userProfile.id)
        .eq('wallet_address', walletAddress)
        .eq('transaction_status', 'pending')
        .single();

      if (existingTx) {
        // Update existing pending transaction
        await supabase
          .from("binder_transactions")
          .update({
            transaction_hash: transactionHash,
            binder_id: binderId,
            transaction_status: 'confirmed',
            blockchain_verified: true,
            updated_at: new Date().toISOString()
          })
          .eq('id', existingTx.id);
      } else {
        // Create new transaction record
        await supabase
          .from("binder_transactions")
          .insert({
            user_profile_id: userProfile.id,
            wallet_address: walletAddress,
            transaction_hash: transactionHash,
            binder_id: binderId,
            transaction_status: 'confirmed',
            blockchain_verified: true
          });
      }

      console.log(`Binder verified: ${binderId} for user: ${walletAddress}`);
    }

    res.json({
      success: true,
      verified: true,
      binderId: binderId,
      transactionHash: transactionHash,
      message: "Binder creation verified successfully"
    });

  } catch (err) {
    console.error("Transaction verification error:", err);
    res.status(500).json({
      success: false,
      verified: false,
      error: "Verification failed: " + err.message
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


app.post("/buy-booster", async (req, res) => {
  if (!requireContractIds(res)) return;

  const { walletAddress, binderId, boosterPackSerial, price, coinType } = req.body;
  if (!walletAddress || !binderId || !boosterPackSerial || !price || !coinType) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }

  try {
    console.log(`Creating buy booster transaction for: ${walletAddress}`);

    const tx = new Transaction();

    // Split coin for payment
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

    // Set gas budget and sender - FIXED: Use setGasBudget instead of setGasLimit
    tx.setSender(walletAddress);
    tx.setGasBudget(15000000); // 0.015 SUI for more complex transaction

    const serializedTx = tx.serialize();
    console.log("Buy booster transaction serialized successfully");

    res.json({
      success: true,
      message: "Booster pack purchase transaction prepared.",
      txBlock: serializedTx,
    });
  } catch (err) {
    console.error("Buy booster error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post("/open-booster", async (req, res) => {
  if (!requireContractIds(res)) return;

  const { walletAddress, binderId, boosterPackSerial } = req.body;
  if (!walletAddress || !binderId || !boosterPackSerial) {
    return res.status(400).json({ success: false, error: "Missing required fields." });
  }


  try {
    console.log(`Creating open booster transaction for: ${walletAddress}`);

    const tx = new Transaction();
    tx.moveCall({
      target: `${SUI_PACKAGE_ID}::booster::open_booster`,
      arguments: [
        tx.object(GLOBAL_CONFIG_ID),
        tx.object(CATALOG_REGISTRY_ID),
        tx.object(CARD_REGISTRY_ID),
        tx.object(binderId),
        tx.pure.string(boosterPackSerial),
        tx.object(RANDOM_ID),
        tx.object(CLOCK_ID),
      ],
    });

    // Set gas budget and sender - FIXED: Use setGasBudget instead of setGasLimit
    tx.setSender(walletAddress);
    tx.setGasBudget(12000000); // 0.012 SUI

    const serializedTx = tx.serialize();
    console.log("Open booster transaction serialized successfully");

    res.json({
      success: true,
      message: "Open booster transaction prepared.",
      txBlock: serializedTx,
    });
  } catch (err) {
    console.error("Open booster error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Contract IDs endpoint (unchanged, commented out for security) -- Optional
// app.get("/contract-ids", (req, res) => {
//   res.json({
//     SUI_PACKAGE_ID,
//     GLOBAL_CONFIG_ID,
//     BINDER_REGISTRY_ID,
//     COSMETICS_REGISTRY_ID,
//     CATALOG_REGISTRY_ID,
//     CARD_REGISTRY_ID,
//     CLOCK_ID,
//     RANDOM_ID,
//   });
// });



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