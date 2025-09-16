// server.js - Final version with user_profiles table
import express from "express";
import bodyParser from "body-parser";
import fetch from "node-fetch";
import { jwtDecode } from "jwt-decode";
import { generateRandomness, jwtToAddress } from "@mysten/sui/zklogin";
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

    // 3️⃣ Check if user exists in user_profiles table
    let { data: userProfile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("email", profile.email)
      .single();

    let salt;
    
    if (userProfile && userProfile.user_salt) {
      // User exists with salt
      salt = userProfile.user_salt;
      console.log("✅ Using existing salt for user:", profile.email);
    } else {
      // New user or user without salt
      salt = generateRandomness().toString();
      console.log("✅ Generated new salt for user:", profile.email);
    }

    // 4️⃣ Decode JWT and derive zkLogin address
    const decodedJwt = jwtDecode(tokens.id_token);
    console.log("✅ Decoded JWT sub:", decodedJwt.sub);
    
    // Convert salt to BigInt
    const saltBigInt = BigInt(salt);
    
    // Derive the zkLogin Sui address directly from JWT and salt
    const suiWallet = jwtToAddress(tokens.id_token, saltBigInt);
    console.log("✅ Generated zkLogin wallet address:", suiWallet);

    // 5️⃣ Upsert user profile
    const profileData = {
      email: profile.email,
      google_id: profile.id,
      name: profile.name,
      picture: profile.picture,
      user_salt: salt,
      sui_address: suiWallet,
      updated_at: new Date().toISOString()
    };

    let finalUserProfile;
    
    if (userProfile) {
      // Update existing user
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
      // Insert new user
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
      profileId: finalUserProfile.id,
      // Store additional data that might be useful for Unity
      sub: decodedJwt.sub,
      aud: decodedJwt.aud
    };

    res.send("✅ Login successful! You can return to your game.");
  } catch (err) {
    console.error("Google callback error:", err);
    res.status(500).send("Auth failed: " + err.message);
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

// 🔹 Health check endpoint
app.get("/ping", (req, res) => {
  res.send("pong");
});

// 🔹 Get user profile by email (for Unity)
app.get("/profile/:email", async (req, res) => {
  const { email } = req.params;
  
  try {
    const { data: profile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("email", email)
      .single();
      
    if (error || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }
    
    res.json({
      email: profile.email,
      name: profile.name,
      picture: profile.picture,
      suiWallet: profile.sui_address
    });
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).send("Profile fetch failed");
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
