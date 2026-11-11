import { supabaseAdmin } from "../_shared/supabaseAdmin.ts";
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const uid = url.searchParams.get("user_id");
  const { data } = await supabaseAdmin.from("orders").select("*").eq("user_id", uid);
  return new Response(JSON.stringify(data));
});
