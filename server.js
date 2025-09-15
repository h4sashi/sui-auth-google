import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';
import { jwtToAddress } from '@mysten/zklogin';
import { createClient as createSupabaseClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const supabase = createSupabaseClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// helper
function generateSalt() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
}

// --- OAUTH2 client for redirect flow ---
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.REDIRECT_URI // e.g. https://your-app.onrender.com/auth/google/callback
);

// STEP 1: Redirect Unity user → Google login
app.get('/auth/google', (req, res) => {
  const state = req.query.state || crypto.randomBytes(8).toString('hex');

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['profile', 'email'],
    state,
  });

  res.redirect(url);
});

// STEP 2: Handle Google OAuth callback
app.get('/auth/google/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;

  try {
    // Exchange code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Verify ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    // Derive zkLogin Sui wallet
    const user_salt = generateSalt();
    const sui_address = jwtToAddress(tokens.id_token, user_salt);

    // Store session in Supabase (replace with your schema)
    await supabase.from('sessions').upsert({
      state,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      sui_wallet: sui_address,
      created_at: new Date().toISOString(),
    });

    // Show simple success page
    res.send("✅ Login successful. You can close this tab and return to the game.");
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Authentication failed");
  }
});

// STEP 3: Unity polls here for profile
app.get('/getProfile', async (req, res) => {
  const { state } = req.query;
  if (!state) return res.status(400).json({ error: 'Missing state' });

  const { data, error } = await supabase
    .from('sessions')
    .select('*')
    .eq('state', state)
    .single();

  if (error || !data) {
    return res.status(404).json({ error: 'Not found yet' });
  }

  console.log("Data object:", data);


 res.json({
  id: data.id,
  email: data.email,
  name: data.name,
  picture: data.picture,
  suiWallet: data.suiWallet, // <-- match casing
});

});

// (OPTIONAL) keep your old /auth/google-login POST route if you want
// for direct id_token submissions

app.listen(process.env.PORT, () => {
  console.log(`ZKLogin backend running on port ${process.env.PORT}`);
});
