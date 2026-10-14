// Alert configuration endpoints (tasks 2.1 and 2.3).
import { api } from "./client";

export const getAlertConfig = () => api.get("/api/alert-config");
export const saveAlertConfig = (data) => api.patch("/api/alert-config", data);
export const sendTestAlert = () => api.post("/api/alert-config/test");
