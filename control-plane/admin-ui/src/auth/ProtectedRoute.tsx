import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";

import type { Role } from "../api/types";
import { useAuth } from "./AuthContext";

export function ProtectedRoute({ children, roles }: { children: ReactNode; roles?: Role[] }) {
  const { isAuthenticated, role } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  if (roles && role && !roles.includes(role)) {
    return (
      <div className="p-6 text-red-700">
        Forbidden — your role (<span className="font-mono">{role}</span>) cannot access this page.
      </div>
    );
  }
  return <>{children}</>;
}
