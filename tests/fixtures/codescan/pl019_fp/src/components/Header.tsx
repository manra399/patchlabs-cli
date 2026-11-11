// note: never trust user_metadata.role for access
export function Header({ user }) {
  const name = user?.user_metadata?.full_name ?? "there";
  const isAdmin = user?.app_metadata?.role === "admin";
  return <h1>Hi {name}{isAdmin ? " (admin)" : ""}</h1>;
}
