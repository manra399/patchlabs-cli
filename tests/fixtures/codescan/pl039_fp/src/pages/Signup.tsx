import { supabase } from "../lib/supabase";
import { z } from "zod";
const schema = z.object({ email: z.string().email(), password: z.string().min(8) });
export async function signup(form: FormData, setForm: any, state: any) {
  const password = String(form.get("password"));
  setForm({ ...state, password: "" });
  await supabase.auth.signUp({ email: String(form.get("email")), password });
  await supabase.auth.updateUser({ password });
  await supabase.from("tokens").select("*").eq("password_reset_token", "x");
  await supabase.from("profiles").insert({ id: "1", display_name: "a" });
}
