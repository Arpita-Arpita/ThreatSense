import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Dashboard from "./pages/Dashboard";
import Placeholder from "./pages/Placeholder";
import DetectionDetail from "./pages/DetectionDetail";
import LogSources from "./pages/LogSources";
import DetectionSettings from "./pages/DetectionSettings";
import { AlertsProvider } from "./context/AlertsContext";
import AlertConfig from "./pages/AlertConfig";
import InitialSetup from "./pages/InitialSetup";
import Detections from "./pages/Detections";
import Account from "./pages/Account";
import IncidentReports from "./pages/IncidentReports";

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          {/* Password recovery (task 1.5). Unauthenticated by design — a
              locked-out admin cannot be behind ProtectedRoute. */}
          {/* Public: nobody can authenticate before the first account
              exists (Section 2.1). The page itself checks setup-status and
              refuses once setup is complete. */}
          <Route path="/setup" element={<InitialSetup />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route element={
            <AlertsProvider>
              <ProtectedRoute />
            </AlertsProvider>
          }>
            <Route path="/" element={<Dashboard />} />
            <Route path="/detections" element={<Detections />} />
            <Route path="/detections/:detectionId" element={<DetectionDetail />} />
            <Route path="/sources" element={<LogSources />} />
            <Route path="/settings" element={<DetectionSettings />} />
            <Route path="/alerts" element={<AlertConfig />} />
            <Route path="/reports" element={<IncidentReports />} />
            <Route path="/account" element={<Account />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
