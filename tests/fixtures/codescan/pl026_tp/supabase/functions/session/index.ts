const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  const cookie = req.headers.get("cookie");
  return new Response(JSON.stringify({ cookie: !!cookie }), { headers: corsHeaders });
});
