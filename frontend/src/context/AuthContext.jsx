import { createContext, useContext, useEffect, useState } from "react";
import * as authApi from "../api/auth";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [admin, setAdmin] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    authApi.me()
      .then(setAdmin)
      .catch(() => setAdmin(null))
      .finally(() => setLoading(false));
  }, []);

  const login = async (email, password) => {
    const me = await authApi.login(email, password);
    setAdmin(me);
    return me;
  };

  const logout = async () => {
    try { await authApi.logout(); } finally { setAdmin(null); }
  };

  // Section 2.1 roles: SUPER_ADMIN and ADMIN operate the system, VIEWER reads.
  // Exposed as one flag so components ask "may I write?" rather than each
  // repeating a role comparison that could drift from the backend policy.
  //
  // This is presentation only. The backend is the authority and returns 403
  // regardless of what the UI shows — see backend/app/middleware/rbac.py.
  // Hiding a control here is a courtesy to the user, never a security
  // boundary: anyone can still call the endpoint directly and will be refused
  // there.
  const canWrite = admin?.role === "SUPER_ADMIN" || admin?.role === "ADMIN";

  return (
    <AuthContext.Provider value={{ admin, loading, login, logout, canWrite }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
