import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { ApiError, api } from "../api/client";
import type { Role } from "../api/types";

interface AuthState {
  token: string | null;
  role: Role | null;
  username: string | null;
}

interface AuthContextValue extends AuthState {
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const STORAGE_KEY = "mlpef.auth";
const EMPTY: AuthState = { token: null, role: null, username: null };

const AuthContext = createContext<AuthContextValue | null>(null);

function loadState(): AuthState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      return JSON.parse(raw) as AuthState;
    }
  } catch {
    // corrupt storage — fall back to logged out
  }
  return EMPTY;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(loadState);

  useEffect(() => {
    if (state.token) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [state]);

  // On mount, validate any persisted token; an expired session logs out.
  useEffect(() => {
    const persisted = loadState();
    if (!persisted.token) {
      return;
    }
    api.me(persisted.token).catch((error: unknown) => {
      if (error instanceof ApiError && error.status === 401) {
        setState(EMPTY);
      }
    });
  }, []);

  const value = useMemo<AuthContextValue>(() => {
    return {
      ...state,
      isAuthenticated: state.token !== null,
      login: async (username: string, password: string) => {
        const result = await api.login(username, password);
        setState({ token: result.token, role: result.role, username });
      },
      logout: () => setState(EMPTY),
    };
  }, [state]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
