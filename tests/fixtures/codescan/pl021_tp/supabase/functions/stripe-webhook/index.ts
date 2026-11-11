import Stripe from "npm:stripe@14";
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await admin.from("subscriptions").upsert({ user_id: event.data.object.client_reference_id, status: "active" });
  }
  return new Response("ok");
});
