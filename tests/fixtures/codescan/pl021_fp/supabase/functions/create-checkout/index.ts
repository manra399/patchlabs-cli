import Stripe from "npm:stripe@14";

Deno.serve(async (req) => {
  const { priceId } = await req.json();
  const session = await stripe.checkout.sessions.create({ line_items: [{ price: priceId, quantity: 1 }], mode: "subscription" });
  return new Response(JSON.stringify({ url: session.url }));
});
