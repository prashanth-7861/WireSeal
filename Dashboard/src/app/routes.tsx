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
import { Backup } from "./pages/Backup";
import { TwoFactor } from "./pages/TwoFactor";
import { Connect } from "./pages/client/Connect";
import { Terminal } from "./pages/client/Terminal";
import { Sftp } from "./pages/client/Sftp";
import { ClientSettings } from "./pages/client/ClientSettings";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      // Server mode routes
      { index: true, Component: Dashboard },
      { path: "clients", Component: Clients },
      { path: "audit-log", Component: AuditLog },
      { path: "security", Component: Security },
      { path: "settings", Component: Settings },
      { path: "admin", Component: Admin },
      { path: "admins", Component: Admins },
      { path: "dns", Component: Dns },
      { path: "two-factor", Component: TwoFactor },
      { path: "backup", Component: Backup },
      // Client mode routes
      { path: "client", Component: Connect },
      { path: "client/terminal", Component: Terminal },
      { path: "client/sftp", Component: Sftp },
      { path: "client/settings", Component: ClientSettings },
      // Shared routes
      { path: "about", Component: About },
    ],
  },
]);
