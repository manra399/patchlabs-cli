import Stripe from "npm:stripe@14";
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature")!;
  const body = await req.text();
  const event = await stripe.webhooks.constructEventAsync(body, sig, Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
  return new Response("ok");
});
