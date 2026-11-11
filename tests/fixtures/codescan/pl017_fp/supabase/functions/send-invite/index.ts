import { supabaseAdmin } from "../_shared/admin.ts";
Deno.serve(async (req) => {
  const token = req.headers.get("Authorization")!.replace("Bearer ", "");
  const { data: { user } } = await supabaseAdmin.auth.getUser(token);
  if (!user) return new Response("unauthorized", { status: 401 });
  return new Response("ok");
});
