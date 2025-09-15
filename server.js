// server.js
import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { jwtDecode } from "jwt-decode";
import { generateNonce, generateRandomness, getZkLoginSignature } from "@mysten/zklogin";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519"; // ✅ FIXED: Correct import path
import supabase from "./supabaseClient.js";

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

// Temporary in-memory session store for Unity polling
const sessions = {}; // { state: profile }

// 🔹 Google OAuth callback (with zkLogin integration)
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

    // 3️⃣ Check if user exists in DB
    let { data: user, error } = await supabase
      .from("users")
      .select("id, email, name, picture, sui_wallet, salt")
      .eq("email", profile.email)
      .single();

    let salt;
    if (user && user.salt) {
      salt = user.salt;
      console.log("✅ Using existing salt for user:", profile.email);
    } else {
      salt = generateRandomness();
      console.log("✅ Generated new salt for user:", profile.email);
      await supabase.from("users").insert([
        {
          id: profile.id,
          email: profile.email,
          name: profile.name,
          picture: profile.picture,
          salt
        }
      ]);
    }

    // 4️⃣ Create ephemeral keypair first
    const ephemeralKeypair = new Ed25519Keypair();
    
    // Generate nonce with correct parameters
    const maxEpoch = Math.floor(Date.now() / 1000) + 24 * 60 * 60; // 24 hours from now
    const nonce = generateNonce(ephemeralKeypair.getPublicKey(), maxEpoch, salt);

    // 5️⃣ Generate zkLogin signature (ephemeralKeypair already created above)
    
    // ✅ IMPROVED: Better error handling for zkLogin signature generation
    let zkLoginSig;
    try {
      zkLoginSig = await getZkLoginSignature({
        inputs: {
          jwt: tokens.id_token,
          ephemeralKeyPair: ephemeralKeypair,
          userSalt: salt,
          jwtRandomness: salt,
          maxEpoch: maxEpoch,
          keyClaimName: "sub"
        }
      });
    } catch (zkError) {
      console.error("zkLogin signature generation failed:", zkError);
      return res.status(500).send("zkLogin wallet generation failed");
    }

    const suiWallet = zkLoginSig.address || ephemeralKeypair.getPublicKey().toSuiAddress();

    // 6️⃣ Update user wallet if missing
    if (!user?.sui_wallet) {
      await supabase
        .from("users")
        .update({ sui_wallet: suiWallet })
        .eq("email", profile.email);
    }

    // 7️⃣ Store session for Unity polling
    sessions[state] = {
      id: profile.id,
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
      suiWallet
    };

    res.send("✅ Login successful! You can return to your game.");
  } catch (err) {
    console.error("Google callback error:", err);
    res.status(500).send("Auth failed.");
  }
});

// 🔹 Unity polling endpoint
app.get("/getProfile", (req, res) => {
  const { state } = req.query;
  if (sessions[state]) {
    res.json(sessions[state]);
    delete sessions[state]; // one-time fetch
  } else {
    res.status(404).send("Not ready");
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));











// import express from 'express';
// import cors from 'cors';
// import dotenv from 'dotenv';
// import { OAuth2Client } from 'google-auth-library';
// import { google } from 'googleapis';
// import { jwtToAddress } from '@mysten/zklogin';
// import { createClient as createSupabaseClient } from '@supabase/supabase-js';
// import crypto from 'crypto';
// import jwt from 'jsonwebtoken';

// dotenv.config();

// const app = express();
// app.use(cors());
// app.use(express.json());

// const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// const supabase = createSupabaseClient(
//   process.env.SUPABASE_URL,
//   process.env.SUPABASE_SERVICE_ROLE_KEY
// );

// // helper
// function generateSalt() {
//   return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
// }

// // --- OAUTH2 client for redirect flow ---
// const oauth2Client = new google.auth.OAuth2(
//   process.env.GOOGLE_CLIENT_ID,
//   process.env.GOOGLE_CLIENT_SECRET,
//   process.env.REDIRECT_URI // e.g. https://your-app.onrender.com/auth/google/callback
// );

// // STEP 1: Redirect Unity user → Google login
// app.get('/auth/google', (req, res) => {
//   const state = req.query.state || crypto.randomBytes(8).toString('hex');

//   const url = oauth2Client.generateAuthUrl({
//     access_type: 'offline',
//     scope: ['profile', 'email'],
//     state,
//   });

//   res.redirect(url);
// });

// // STEP 2: Handle Google OAuth callback
// app.get('/auth/google/callback', async (req, res) => {
//   const code = req.query.code;
//   const state = req.query.state;

//   try {
//     // Exchange code for tokens
//     const { tokens } = await oauth2Client.getToken(code);
//     oauth2Client.setCredentials(tokens);

//     // Verify ID token
//     const ticket = await googleClient.verifyIdToken({
//       idToken: tokens.id_token,
//       audience: process.env.GOOGLE_CLIENT_ID,
//     });
//     const payload = ticket.getPayload();

//     // Derive zkLogin Sui wallet
//     const user_salt = generateSalt();
//     const sui_address = jwtToAddress(tokens.id_token, user_salt);

//     // Store session in Supabase (replace with your schema)
//     await supabase.from('sessions').upsert({
//       state,
//       email: payload.email,
//       name: payload.name,
//       picture: payload.picture,
//       sui_wallet: sui_address,
//       created_at: new Date().toISOString(),
//     });

//     // Show simple success page
//     res.send("✅ Login successful. You can close this tab and return to the game.");
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("❌ Authentication failed");
//   }
// });

// // STEP 3: Unity polls here for profile
// app.get('/getProfile', async (req, res) => {
//   const { state } = req.query;
//   if (!state) return res.status(400).json({ error: 'Missing state' });

//   const { data, error } = await supabase
//     .from('sessions')
//     .select('*')
//     .eq('state', state)
//     .single();

//   if (error || !data) {
//     return res.status(404).json({ error: 'Not found yet' });
//   }

//   console.log("Data object:", data);


//  res.json({
//   id: data.id,
//   email: data.email,
//   name: data.name,
//   picture: data.picture,
//   suiWallet: data.suiWallet, // <-- match casing
// });

// });

// // (OPTIONAL) keep your old /auth/google-login POST route if you want
// // for direct id_token submissions

// app.listen(process.env.PORT, () => {
//   console.log(`ZKLogin backend running on port ${process.env.PORT}`);
// });
