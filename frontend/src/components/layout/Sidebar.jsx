import {
  Activity,
  AlertTriangle,
  Bell,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Settings,
  Shield,
  ShieldCheck,
  Users,
  Workflow,
  X,
} from "lucide-react";
import { NavLink } from "react-router-dom";

import "./Sidebar.css";

const navigationSections = [
  {
    label: "Overview",
    items: [
      {
        label: "Dashboard",
        icon: LayoutDashboard,
        path: "/",
      },
    ],
  },
  {
    label: "Detection",
    items: [
      {
        label: "Alerts",
        icon: Bell,
        path: "/alerts",
        badge: "12",
      },
      {
        label: "Detection Rules",
        icon: FileSearch,
        path: "/detections",
      },
    ],
  },
  {
    label: "Response",
    items: [
      {
        label: "Incidents",
        icon: AlertTriangle,
        path: "/incidents",
        badge: "4",
      },
      {
        label: "Playbooks",
        icon: Workflow,
        path: "/playbooks",
      },
    ],
  },
  {
    label: "Telemetry",
    items: [
      {
        label: "Security Events",
        icon: Activity,
        path: "/events",
      },
    ],
  },
  {
    label: "Administration",
    items: [
      {
        label: "Users",
        icon: Users,
        path: "/users",
      },
      {
        label: "Settings",
        icon: Settings,
        path: "/settings",
      },
    ],
  },
];

function Sidebar({
  collapsed,
  mobileOpen,
  onToggleCollapse,
  onCloseMobile,
}) {
  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          className="sidebar__mobile-overlay"
          aria-label="Close navigation"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={[
          "sidebar",
          collapsed ? "sidebar--collapsed" : "",
          mobileOpen ? "sidebar--mobile-open" : "",
        ]
          .filter(Boolean)
          .join(" ")}
      >
        <div className="sidebar__header">
          <NavLink
            to="/"
            className="sidebar__brand"
            onClick={onCloseMobile}
          >
            <span className="sidebar__brand-mark">
              <ShieldCheck size={21} strokeWidth={2.2} />
            </span>

            <span className="sidebar__brand-copy">
              <span className="sidebar__brand-name">
                CYBERDEFENSE
                <span>-X</span>
              </span>

              <span className="sidebar__brand-subtitle">
                SECURITY OPERATIONS
              </span>
            </span>
          </NavLink>

          <button
            type="button"
            className="sidebar__mobile-close"
            aria-label="Close navigation"
            onClick={onCloseMobile}
          >
            <X size={18} />
          </button>
        </div>

        <div className="sidebar__system-status">
          <span className="sidebar__status-indicator">
            <CircleDot size={11} />
          </span>

          <span className="sidebar__system-copy">
            <span className="sidebar__system-label">
              SYSTEM STATUS
            </span>

            <span className="sidebar__system-value">
              All systems operational
            </span>
          </span>
        </div>

        <nav className="sidebar__navigation" aria-label="Primary navigation">
          {navigationSections.map((section) => (
            <div className="sidebar__section" key={section.label}>
              <div className="sidebar__section-label">
                {section.label}
              </div>

              <div className="sidebar__items">
                {section.items.map((item) => {
                  const Icon = item.icon;

                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      end={item.path === "/"}
                      className={({ isActive }) =>
                        [
                          "sidebar__item",
                          isActive ? "sidebar__item--active" : "",
                        ]
                          .filter(Boolean)
                          .join(" ")
                      }
                      onClick={onCloseMobile}
                      title={collapsed ? item.label : undefined}
                    >
                      <span className="sidebar__item-icon">
                        <Icon size={18} strokeWidth={1.9} />
                      </span>

                      <span className="sidebar__item-label">
                        {item.label}
                      </span>

                      {item.badge && (
                        <span className="sidebar__item-badge">
                          {item.badge}
                        </span>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="sidebar__environment">
            <span className="sidebar__environment-icon">
              <Shield size={16} />
            </span>

            <span className="sidebar__environment-copy">
              <span>DEFENSE NODE</span>
              <strong>LOCAL / SECURE</strong>
            </span>
          </div>

          <button
            type="button"
            className="sidebar__logout"
            title={collapsed ? "Sign out" : undefined}
          >
            <LogOut size={17} />
            <span>Sign out</span>
          </button>

          <button
            type="button"
            className="sidebar__collapse"
            onClick={onToggleCollapse}
            aria-label={
              collapsed
                ? "Expand navigation"
                : "Collapse navigation"
            }
          >
            {collapsed ? (
              <ChevronRight size={17} />
            ) : (
              <ChevronLeft size={17} />
            )}

            <span>{collapsed ? "Expand" : "Collapse"} sidebar</span>
          </button>
        </div>
      </aside>
    </>
  );
}

export default Sidebar;