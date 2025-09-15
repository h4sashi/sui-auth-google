import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';
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

function generateSalt() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString();
}

// Google login → zkLogin
app.post('/auth/google-login', async (req, res) => {
  const { id_token } = req.body;
  if (!id_token) return res.status(400).json({ error: 'Missing id_token' });

  // 1. Verify Google token
  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid Google token' });
  }

  const oauth_provider = 'google';
  const oauth_sub = payload.sub;

  // 2. Find or create user
  let { data: user } = await supabase
    .from('users')
    .select('*')
    .eq('oauth_provider', oauth_provider)
    .eq('oauth_sub', oauth_sub)
    .single();

  let user_salt;
  let user_id;

  if (!user) {
    user_salt = generateSalt();
    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        oauth_provider,
        oauth_sub,
        user_salt,
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });
    user = newUser;
  }

  user_salt = user.user_salt;
  user_id = user.id;

  // 3. Derive Sui address from JWT + salt
  let sui_address;
  try {
    sui_address = jwtToAddress(id_token, user_salt);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to derive Sui address' });
  }

  // 4. Update DB if new
  await supabase
    .from('users')
    .update({ sui_address, last_login: new Date().toISOString() })
    .eq('id', user_id);

  // 5. Create session token
  const sessionToken = jwt.sign(
    { user_id, sui_address },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ user_id, sui_address, session_token: sessionToken });
});

app.listen(process.env.PORT, () => {
  console.log(`ZKLogin backend running on port ${process.env.PORT}`);
});
