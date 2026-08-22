import { useState } from "react";
import { Outlet } from "react-router-dom";

import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

import "./AppShell.css";

function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleToggleSidebar = () => {
    setSidebarCollapsed((current) => !current);
  };

  const handleOpenMobileMenu = () => {
    setMobileMenuOpen(true);
  };

  const handleCloseMobileMenu = () => {
    setMobileMenuOpen(false);
  };

  return (
    <div
      className={[
        "app-shell",
        sidebarCollapsed ? "app-shell--sidebar-collapsed" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <Sidebar
        collapsed={sidebarCollapsed}
        mobileOpen={mobileMenuOpen}
        onToggleCollapse={handleToggleSidebar}
        onCloseMobile={handleCloseMobileMenu}
      />

      <Topbar onOpenMobileMenu={handleOpenMobileMenu} />

      <main className="app-shell__main">
        <div className="app-shell__content">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

export default AppShell;