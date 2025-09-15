import express from "express";
import bodyParser from "body-parser";
import { jwtDecode } from "jwt-decode";
import { generateNonce, generateRandomness, getZkLoginSignature } from "@mysten/zklogin";
import { Ed25519Keypair } from "@mysten/sui.js/keypairs/ed25519";
import supabase from "./supabaseClient.js"; // your Supabase client

const app = express();
app.use(bodyParser.json());

app.post("/auth/google/callback", async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Missing Google credential" });

    const decoded = jwtDecode(credential);

    // 1️⃣ Check if user exists in DB
    let { data: user, error } = await supabase
      .from("users")
      .select("id, email, name, picture, sui_wallet, salt")
      .eq("email", decoded.email)
      .single();

    let salt;
    if (user && user.salt) {
      // User already exists → use stored salt
      salt = user.salt;
    } else {
      // New user → generate and store salt
      salt = generateRandomness();

      const { error: insertErr } = await supabase.from("users").insert([
        {
          email: decoded.email,
          name: decoded.name,
          picture: decoded.picture,
          salt,
        },
      ]);
      if (insertErr) throw insertErr;
    }

    // 2️⃣ Generate zkLogin nonce
    const nonce = generateNonce(salt, decoded.sub);

    // 3️⃣ Ephemeral keypair for login proof
    const ephemeralKeypair = new Ed25519Keypair();

    // 4️⃣ zkLogin signature → derive wallet
    const zkLoginSig = await getZkLoginSignature({
      jwt: credential,
      ephemeralKeypair,
      nonce,
      salt,
    });
    const suiWallet = zkLoginSig.address;

    // 5️⃣ Update user with wallet if not stored
    if (!user?.sui_wallet) {
      await supabase
        .from("users")
        .update({ sui_wallet: suiWallet })
        .eq("email", decoded.email);
    }

    // 6️⃣ Return profile + wallet
    res.json({
      id: decoded.sub,
      email: decoded.email,
      name: decoded.name,
      picture: decoded.picture,
      suiWallet,
    });
  } catch (err) {
    console.error("zkLogin persistent error:", err);
    res.status(500).json({ error: "zkLogin persistent integration failed", details: err.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));

















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
