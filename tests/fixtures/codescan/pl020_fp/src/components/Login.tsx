export function Login() {
  const theme = localStorage.getItem("theme");
  return <input type="email" placeholder="admin@example.com" className={theme} />;
}
