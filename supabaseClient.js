// supabaseClient.js
import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // use service role for writes
if (!supabaseUrl || !supabaseKey) {
  throw new Error("Missing Supabase credentials. Check your .env file.");
}

const supabase = createClient(supabaseUrl, supabaseKey);

export default supabase;
