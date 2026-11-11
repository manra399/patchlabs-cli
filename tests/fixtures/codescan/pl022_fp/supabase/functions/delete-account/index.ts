import { createClient } from "npm:@supabase/supabase-js@2";
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const authHeader = req.headers.get("Authorization")!;
  const { data: { user } } = await admin.auth.getUser(authHeader.replace("Bearer ", ""));
  const { reason, userId } = await req.json();
  await admin.auth.admin.deleteUser(user!.id);
  return new Response("deleted");
});
