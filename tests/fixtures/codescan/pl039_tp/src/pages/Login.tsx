import { supabase } from "../lib/supabase";
export async function login(email: string, password: string) {
  const { data } = await supabase.from("users").select("*").eq("email", email).eq("password", password).single();
  return data;
}
