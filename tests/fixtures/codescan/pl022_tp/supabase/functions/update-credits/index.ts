const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const body = await req.json();
  await admin.from("credits").update({ amount: body.amount }).eq("owner_id", body.owner_id);
  return new Response("ok");
});
