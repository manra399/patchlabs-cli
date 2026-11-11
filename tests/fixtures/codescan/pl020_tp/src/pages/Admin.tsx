export default function Admin() {
  if (localStorage.getItem("isAdmin") !== "true") return <Navigate to="/" />;
  return <AdminDashboard />;
}
