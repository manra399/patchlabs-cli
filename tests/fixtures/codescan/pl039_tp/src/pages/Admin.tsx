  // TODO hash later
export const q = (s: any, password: string) => s.from("admins").select("id").eq("password", password) // usar hash depois
