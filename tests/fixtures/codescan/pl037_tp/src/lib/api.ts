import { supabase } from "./supabase";

export async function loadOrders(user: { id: string; email: string; phone: string }) {
  const res = await fetch("/api/orders", {
    headers: {
      "Content-Type": "application/json",
      "X-User-Email": user.email,
      "X-Phone": user.phone,
    },
  });
  return res.json();
}

export function track(req: Request, user: any) {
  const h = new Headers();
  h.set("X-Customer-Id", user.ssn);
  h.set("X-Support-Contact", "jane.doe@acme-corp.io");
  return h;
}
