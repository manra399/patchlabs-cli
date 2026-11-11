import { createClient } from "npm:@supabase/supabase-js@2";
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const { userId, reason } = await req.json();
  await admin.auth.admin.deleteUser(userId);
  return new Response("deleted");
});
