import { api } from "./client";

export const login = (email, password) => api.post("/api/auth/login", { email, password });
export const logout = () => api.post("/api/auth/logout");
export const me = () => api.get("/api/auth/me");

// Password recovery (task 1.5, Section 2.1). The request endpoint always
// returns the same generic message whether or not the email matches an
// account, so callers must not infer existence from a success response.
export const requestPasswordReset = (email) =>
  api.post("/api/auth/password-reset/request", { email });

export const confirmPasswordReset = (token, newPassword) =>
  api.post("/api/auth/password-reset/confirm", { token, new_password: newPassword });

// The NFR-11 rules as the server states them. frontend/src/lib/passwordPolicy.js
// carries its own regex copy (the requirement asks for client-side regex
// validation); this endpoint exists so the wording shown to the administrator
// can be sourced from one place if the two ever need reconciling.
export const getPasswordPolicy = () => api.get("/api/auth/password-policy");

// Initial administrator setup (Section 2.1, Figure 3). Both are public: the
// login screen calls getSetupStatus before anyone can authenticate, to decide
// whether to show the Initial Setup link.
export const getSetupStatus = () => api.get("/api/auth/setup-status");

export const initialSetup = (fullName, email, password) =>
  api.post("/api/auth/setup", { full_name: fullName, email, password });

// Change your own password while signed in (Section 2.1, Account Settings).
// Distinct from the reset flow, which is for someone who cannot sign in.
export const changePassword = (currentPassword, newPassword) =>
  api.post("/api/auth/change-password", {
    current_password: currentPassword, new_password: newPassword,
  });

// Account management (Section 2.1). SUPER_ADMIN only — the backend enforces
// that; the UI simply does not render the section for other roles.
// Listing and creation only: accounts are never deleted, because audit_logs
// references the administrator who performed each action.
export const listAccounts = () => api.get("/api/accounts");
export const createAccount = (body) => api.post("/api/accounts", body);
