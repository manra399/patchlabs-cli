const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  const auth = req.headers.get("Authorization");
  const { data: { user } } = await supabase.auth.getUser(auth!.replace("Bearer ", ""));
  return new Response(JSON.stringify(user), { headers: corsHeaders });
});
