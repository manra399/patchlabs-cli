import { createClient } from "npm:@supabase/supabase-js@2";
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const { email } = await req.json();
  await admin.from("profiles").delete().eq("email", email);
  return new Response("ok");
});
