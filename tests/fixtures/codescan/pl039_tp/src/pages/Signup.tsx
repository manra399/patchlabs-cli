import { supabase } from "../lib/supabase";
export async function signup(email: string, name: string, password: string) {
  const { error } = await supabase.from("users").insert({
    email,
    name,
    password,
  });
  return error;
}
