import { supabase } from "./supabase";

export async function loadOrders(user: { id: string; email: string }, token: string) {
  // "X-User-Email": user.email  <- old version, removed
  const res = await fetch("/api/orders", {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "X-User-Id": user.id,
      "X-Request-Id": crypto.randomUUID(),
      "X-Contact": "support@example.com",
    },
  });
  const { data } = await supabase.from("profiles").select("email").eq("id", user.id);
  return { orders: await res.json(), email: user.email };
}
