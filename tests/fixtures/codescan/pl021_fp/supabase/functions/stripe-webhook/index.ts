import Stripe from "npm:stripe@14";

Deno.serve(async (req) => {
  const signature = req.headers.get("stripe-signature");
  const body = await req.text();
  const event = await stripe.webhooks.constructEventAsync(body, signature!, Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
  return new Response(JSON.stringify({ received: event.id }));
});
