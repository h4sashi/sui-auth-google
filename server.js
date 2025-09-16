// server.js - Enhanced with better validation and CORS support
import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { jwtDecode } from "jwt-decode";
import { generateRandomness, jwtToAddress } from "@mysten/sui/zklogin";
import { isValidSuiAddress } from "@mysten/sui/utils";
import supabase from "./supabaseClient.js";

const app = express();

// 🔹 CORS middleware - CRITICAL for Unity WebGL
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

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
  }
  next();
});

const PORT = process.env.PORT || 3000;

// Temporary in-memory session store for Unity polling
const sessions = {}; // { state: profile }

// 🔹 Enhanced wallet validation with detailed logging
app.post("/validate-wallet", (req, res) => {
  console.log("🔍 Wallet validation request received");
  console.log("Headers:", req.headers);
  console.log("Body:", req.body);
  
  try {
    const { address } = req.body;
    
    console.log(`🔍 Validating address: ${address}`);
    
    // Check if address is provided
    if (!address) {
      console.log("❌ No address provided");
      return res.status(400).json({
        valid: false,
        address: null,
        message: "No wallet address provided"
      });
    }
    
    // Check if address is a string
    if (typeof address !== 'string') {
      console.log("❌ Address is not a string:", typeof address);
      return res.status(400).json({
        valid: false,
        address: address,
        message: "Wallet address must be a string"
      });
    }
    
    // Trim whitespace
    const cleanAddress = address.trim();
    console.log(`🔍 Cleaned address: ${cleanAddress}`);
    
    // Validate using Sui SDK
    const isValid = isValidSuiAddress(cleanAddress);
    console.log(`🔍 Sui SDK validation result: ${isValid}`);
    
    // Additional manual checks for common issues
    let additionalInfo = "";
    
    if (!cleanAddress.startsWith('0x')) {
      additionalInfo += " (Missing 0x prefix)";
    } else if (cleanAddress.length !== 66) { // 0x + 64 hex characters
      additionalInfo += ` (Wrong length: ${cleanAddress.length}, should be 66)`;
    } else if (!/^0x[a-fA-F0-9]{64}$/.test(cleanAddress)) {
      additionalInfo += " (Contains invalid characters)";
    }
    
    const responseData = {
      valid: isValid,
      address: cleanAddress,
      message: isValid 
        ? "Valid Sui address" 
        : `Invalid Sui address format${additionalInfo}`
    };
    
    console.log("📤 Sending response:", responseData);
    res.json(responseData);
    
  } catch (err) {
    console.error("❌ Validation error:", err);
    res.status(500).json({
      valid: false,
      address: req.body?.address || null,
      message: "Server error during validation: " + err.message
    });
  }
});

// 🔹 Test endpoint to verify server is working
app.get("/test-validation", (req, res) => {
  const testAddress = "0x59435d7c7acd3a3d17c8701d9384b25fdafd7669307dea06a8a70c8bd3fb52d0";
  const isValid = isValidSuiAddress(testAddress);
  
  res.json({
    testAddress,
    isValid,
    message: `Test validation: ${isValid ? 'PASSED' : 'FAILED'}`,
    serverTime: new Date().toISOString()
  });
});

// 🔹 Google OAuth callback (zkLogin path)
app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;
  
  try {
    // 1️⃣ Exchange code for tokens
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        redirect_uri: process.env.REDIRECT_URI,
        grant_type: "authorization_code"
      })
    });
    
    const tokens = await tokenRes.json();
    if (tokens.error) {
      console.error("Token exchange failed:", tokens);
      return res.status(400).send("Token exchange failed");
    }

    // 2️⃣ Fetch Google profile
    const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const profile = await profileRes.json();
    
    console.log("✅ Google profile:", { id: profile.id, email: profile.email, name: profile.name });

    // 3️⃣ Check if user exists in user_profiles table
    let { data: userProfile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("email", profile.email)
      .single();

    let salt;
    
    if (userProfile && userProfile.user_salt) {
      salt = userProfile.user_salt;
      console.log("✅ Using existing salt for user:", profile.email);
    } else {
      salt = generateRandomness().toString();
      console.log("✅ Generated new salt for user:", profile.email);
    }

    // 4️⃣ Decode JWT and derive zkLogin address
    const decodedJwt = jwtDecode(tokens.id_token);
    const saltBigInt = BigInt(salt);
    const suiWallet = jwtToAddress(tokens.id_token, saltBigInt);

    // 5️⃣ Upsert user profile
    const profileData = {
      email: profile.email,
      google_id: profile.id,
      name: profile.name,
      picture: profile.picture,
      user_salt: salt,
      sui_address: suiWallet,
      auth_method: "zklogin", // Mark as zkLogin user
      updated_at: new Date().toISOString()
    };

    let finalUserProfile;
    
    if (userProfile) {
      const { data: updated, error: updateError } = await supabase
        .from("user_profiles")
        .update(profileData)
        .eq("id", userProfile.id)
        .select()
        .single();
        
      if (updateError) {
        console.error("Profile update error:", updateError);
        return res.status(500).send("Profile update failed");
      }
      finalUserProfile = updated;
    } else {
      const { data: inserted, error: insertError } = await supabase
        .from("user_profiles")
        .insert([profileData])
        .select()
        .single();
        
      if (insertError) {
        console.error("Profile insert error:", insertError);
        return res.status(500).send("Profile creation failed");
      }
      finalUserProfile = inserted;
    }

    // 6️⃣ Store session for Unity polling
    sessions[state] = {
      id: profile.id,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
      suiWallet,
      authMethod: "zklogin",
      profileId: finalUserProfile.id,
      sub: decodedJwt.sub,
      aud: decodedJwt.aud
    };

    res.send("✅ zkLogin successful! You can return to your game.");
  } catch (err) {
    console.error("Google callback error:", err);
    res.status(500).send("Auth failed: " + err.message);
  }
});

// 🔹 Manual wallet connection endpoint
app.post("/auth/wallet", async (req, res) => {
  const { walletAddress, playerName, state } = req.body;
  
  try {
    // 1️⃣ Validate the Sui address format
    if (!walletAddress || !isValidSuiAddress(walletAddress)) {
      return res.status(400).json({ 
        success: false,
        error: "Invalid Sui wallet address format" 
      });
    }
    
    console.log("✅ Manual wallet connection:", { walletAddress, playerName });
    
    // 2️⃣ Check if this wallet is already registered
    let { data: existingProfile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("sui_address", walletAddress)
      .single();
    
    let finalProfile;
    
    if (existingProfile) {
      // 3️⃣ Wallet exists - update last login
      const { data: updated, error: updateError } = await supabase
        .from("user_profiles")
        .update({ 
          updated_at: new Date().toISOString(),
          name: playerName || existingProfile.name // Update name if provided
        })
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
      console.log("✅ Existing wallet user updated");
    } else {
      // 4️⃣ New wallet - create profile
      const profileData = {
        email: null, // No email for manual wallet users
        google_id: null,
        name: playerName || `Player_${walletAddress.substring(0, 8)}`,
        picture: null,
        user_salt: null, // Not needed for manual wallets
        sui_address: walletAddress,
        auth_method: "manual_wallet",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
      const { data: inserted, error: insertError } = await supabase
        .from("user_profiles")
        .insert([profileData])
        .select()
        .single();
        
      if (insertError) {
        console.error("Profile insert error:", insertError);
        return res.status(500).json({ 
          success: false,
          error: "Profile creation failed" 
        });
      }
      
      finalProfile = inserted;
      console.log("✅ New wallet user created");
    }
    
    // 5️⃣ Store session for Unity polling (if state provided)
    if (state) {
      sessions[state] = {
        id: walletAddress.substring(0, 16), // Use wallet prefix as ID
        email: finalProfile.email,
        name: finalProfile.name,
        picture: finalProfile.picture,
        suiWallet: walletAddress,
        authMethod: "manual_wallet",
        profileId: finalProfile.id
      };
    }
    
    // 6️⃣ Return success response
    res.json({
      success: true,
      message: "Wallet connected successfully",
      profile: {
        id: finalProfile.id,
        name: finalProfile.name,
        suiWallet: walletAddress,
        authMethod: "manual_wallet",
        isExisting: !!existingProfile
      }
    });
    
  } catch (err) {
    console.error("Manual wallet connection error:", err);
    res.status(500).json({ 
      success: false,
      error: "Wallet connection failed: " + err.message 
    });
  }
});

// 🔹 Unity polling endpoint (works for both auth methods)
app.get("/getProfile", (req, res) => {
  const { state } = req.query;
  if (sessions[state]) {
    res.json(sessions[state]);
    delete sessions[state]; // one-time fetch
  } else {
    res.status(404).send("Not ready");
  }
});

// 🔹 Get user profile by wallet address
app.get("/profile/wallet/:address", async (req, res) => {
  const { address } = req.params;
  
  try {
    if (!isValidSuiAddress(address)) {
      return res.status(400).json({ error: "Invalid wallet address" });
    }
    
    const { data: profile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("sui_address", address)
      .single();
      
    if (error || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }
    
    res.json({
      id: profile.id,
      name: profile.name,
      picture: profile.picture,
      suiWallet: profile.sui_address,
      authMethod: profile.auth_method,
      email: profile.email,
      createdAt: profile.created_at
    });
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).send("Profile fetch failed");
  }
});

// 🔹 Health check endpoint
app.get("/ping", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    message: "Server is running"
  });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));


























// // server.js - Final version with user_profiles table
// import express from "express";
// import bodyParser from "body-parser";
// import fetch from "node-fetch";
// import { jwtDecode } from "jwt-decode";
// import { generateRandomness, jwtToAddress } from "@mysten/sui/zklogin";
// import supabase from "./supabaseClient.js";

// const app = express();
// app.use(bodyParser.json());
// const PORT = process.env.PORT || 3000;

// // Temporary in-memory session store for Unity polling
// const sessions = {}; // { state: profile }

// // 🔹 Google OAuth callback (with zkLogin integration)
// app.get("/auth/google/callback", async (req, res) => {
//   const { code, state } = req.query;
  
//   try {
//     // 1️⃣ Exchange code for tokens
//     const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
//       method: "POST",
//       headers: { "Content-Type": "application/x-www-form-urlencoded" },
//       body: new URLSearchParams({
//         client_id: process.env.GOOGLE_CLIENT_ID,
//         client_secret: process.env.GOOGLE_CLIENT_SECRET,
//         code,
//         redirect_uri: process.env.REDIRECT_URI,
//         grant_type: "authorization_code"
//       })
//     });
    
//     const tokens = await tokenRes.json();
//     if (tokens.error) {
//       console.error("Token exchange failed:", tokens);
//       return res.status(400).send("Token exchange failed");
//     }

//     // 2️⃣ Fetch Google profile
//     const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
//       headers: { Authorization: `Bearer ${tokens.access_token}` }
//     });
//     const profile = await profileRes.json();
    
//     console.log("✅ Google profile:", { id: profile.id, email: profile.email, name: profile.name });

//     // 3️⃣ Check if user exists in user_profiles table
//     let { data: userProfile, error } = await supabase
//       .from("user_profiles")
//       .select("*")
//       .eq("email", profile.email)
//       .single();

//     let salt;
    
//     if (userProfile && userProfile.user_salt) {
//       // User exists with salt
//       salt = userProfile.user_salt;
//       console.log("✅ Using existing salt for user:", profile.email);
//     } else {
//       // New user or user without salt
//       salt = generateRandomness().toString();
//       console.log("✅ Generated new salt for user:", profile.email);
//     }

//     // 4️⃣ Decode JWT and derive zkLogin address
//     const decodedJwt = jwtDecode(tokens.id_token);
//     console.log("✅ Decoded JWT sub:", decodedJwt.sub);
    
//     // Convert salt to BigInt
//     const saltBigInt = BigInt(salt);
    
//     // Derive the zkLogin Sui address directly from JWT and salt
//     const suiWallet = jwtToAddress(tokens.id_token, saltBigInt);
//     console.log("✅ Generated zkLogin wallet address:", suiWallet);

//     // 5️⃣ Upsert user profile
//     const profileData = {
//       email: profile.email,
//       google_id: profile.id,
//       name: profile.name,
//       picture: profile.picture,
//       user_salt: salt,
//       sui_address: suiWallet,
//       updated_at: new Date().toISOString()
//     };

//     let finalUserProfile;
    
//     if (userProfile) {
//       // Update existing user
//       const { data: updated, error: updateError } = await supabase
//         .from("user_profiles")
//         .update(profileData)
//         .eq("id", userProfile.id)
//         .select()
//         .single();
        
//       if (updateError) {
//         console.error("Profile update error:", updateError);
//         return res.status(500).send("Profile update failed");
//       }
//       finalUserProfile = updated;
//     } else {
//       // Insert new user
//       const { data: inserted, error: insertError } = await supabase
//         .from("user_profiles")
//         .insert([profileData])
//         .select()
//         .single();
        
//       if (insertError) {
//         console.error("Profile insert error:", insertError);
//         return res.status(500).send("Profile creation failed");
//       }
//       finalUserProfile = inserted;
//     }

//     // 6️⃣ Store session for Unity polling
//     sessions[state] = {
//       id: profile.id,
//       email: profile.email,
//       name: profile.name,
//       picture: profile.picture,
//       suiWallet,
//       profileId: finalUserProfile.id,
//       // Store additional data that might be useful for Unity
//       sub: decodedJwt.sub,
//       aud: decodedJwt.aud
//     };

//     res.send("✅ Login successful! You can return to your game.");
//   } catch (err) {
//     console.error("Google callback error:", err);
//     res.status(500).send("Auth failed: " + err.message);
//   }
// });

// // 🔹 Unity polling endpoint
// app.get("/getProfile", (req, res) => {
//   const { state } = req.query;
//   if (sessions[state]) {
//     res.json(sessions[state]);
//     delete sessions[state]; // one-time fetch
//   } else {
//     res.status(404).send("Not ready");
//   }
// });

// // 🔹 Health check endpoint
// app.get("/ping", (req, res) => {
//   res.send("pong");
// });

// // 🔹 Get user profile by email (for Unity)
// app.get("/profile/:email", async (req, res) => {
//   const { email } = req.params;
  
//   try {
//     const { data: profile, error } = await supabase
//       .from("user_profiles")
//       .select("*")
//       .eq("email", email)
//       .single();
      
//     if (error || !profile) {
//       return res.status(404).json({ error: "Profile not found" });
//     }
    
//     res.json({
//       email: profile.email,
//       name: profile.name,
//       picture: profile.picture,
//       suiWallet: profile.sui_address
//     });
//   } catch (err) {
//     console.error("Profile fetch error:", err);
//     res.status(500).send("Profile fetch failed");
//   }
// });

// app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
