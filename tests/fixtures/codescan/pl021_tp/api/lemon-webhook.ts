// Lemon Squeezy webhook
export default async function handler(req, res) {
  const payload = req.body;
  if (payload.meta.event_name === "order_created") await grantAccess(payload.data);
  res.status(200).end();
}
