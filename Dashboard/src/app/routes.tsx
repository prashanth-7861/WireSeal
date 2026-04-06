import { createBrowserRouter } from "react-router";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Clients } from "./pages/Clients";
import { AuditLog } from "./pages/AuditLog";
import { Security } from "./pages/Security";
import { Settings } from "./pages/Settings";
import { About } from "./pages/About";
import { Admin } from "./pages/Admin";
import { Admins } from "./pages/Admins";
import { Dns } from "./pages/Dns";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Dashboard },
      { path: "clients", Component: Clients },
      { path: "audit-log", Component: AuditLog },
      { path: "security", Component: Security },
      { path: "settings", Component: Settings },
      { path: "admin", Component: Admin },
      { path: "admins", Component: Admins },
      { path: "dns", Component: Dns },
      { path: "about", Component: About },
    ],
  },
]);
