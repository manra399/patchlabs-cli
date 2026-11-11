import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization")! } } });
  const { userId } = await req.json();
  const { data } = await supabase.from("orders").select("*").eq("user_id", userId);
  return new Response(JSON.stringify(data));
});
