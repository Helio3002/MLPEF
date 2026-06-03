import { NavLink, Outlet } from "react-router-dom";

import { useAuth } from "../auth/AuthContext";

const NAV_ITEMS = [
  { to: "/agents", label: "Agents" },
  { to: "/profiles", label: "Profiles" },
  { to: "/tools", label: "Tools" },
  { to: "/hitl", label: "HITL Queue" },
  { to: "/audit", label: "Audit" },
  { to: "/dashboard", label: "Dashboard" },
];

export function Layout() {
  const { username, role, logout } = useAuth();
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b bg-white px-6 py-3">
        <div className="flex items-center gap-6">
          <span className="text-lg font-semibold">MLPEF Admin</span>
          <nav className="flex flex-wrap gap-1">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `rounded px-3 py-1 text-sm ${
                    isActive ? "bg-gray-900 text-white" : "text-gray-700 hover:bg-gray-100"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-gray-500">{username}</span>
          <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs">{role}</span>
          <button
            type="button"
            onClick={logout}
            className="rounded border px-3 py-1 hover:bg-gray-100"
          >
            Log out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl p-6">
        <Outlet />
      </main>
      <footer className="px-6 py-4 text-center text-xs text-gray-400">
        MLPEF is measurable defense-in-depth, not a guarantee — see THREAT_MODEL.md.
      </footer>
    </div>
  );
}
