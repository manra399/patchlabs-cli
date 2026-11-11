import { useAuth } from "./useAuth";
export function useIsAdmin() {
  const { user } = useAuth();
  return user?.user_metadata?.role === "admin";
}
