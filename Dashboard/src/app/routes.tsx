import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Clients } from "./pages/Clients";
import { AuditLog } from "./pages/AuditLog";
import { Settings } from "./pages/Settings";
import { About } from "./pages/About";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "clients", Component: Clients },
      { path: "audit-log", Component: AuditLog },
      { path: "settings", Component: Settings },
      { path: "about", Component: About },
    ],
  },
]);
