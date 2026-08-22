import {
  Bell,
  Clock3,
  Menu,
  Search,
  ShieldCheck,
} from "lucide-react";

import "./Topbar.css";

function Topbar({ onOpenMobileMenu }) {
  return (
    <header className="topbar">
      <div className="topbar__left">
        <button
          type="button"
          className="topbar__mobile-menu"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation"
        >
          <Menu size={20} />
        </button>

        <div className="topbar__context">
          <div className="topbar__context-icon">
            <ShieldCheck size={17} />
          </div>

          <div className="topbar__context-copy">
            <span className="topbar__eyebrow">
              SECURITY OPERATIONS CENTER
            </span>

            <span className="topbar__title">
              Defense Console
            </span>
          </div>
        </div>
      </div>

      <div className="topbar__right">
        <div className="topbar__system">
          <span className="topbar__system-dot" />
          <span>OPERATIONAL</span>
        </div>

        <div className="topbar__divider" />

        <div className="topbar__clock">
          <Clock3 size={14} />
          <span>LOCAL NODE</span>
          <strong>23:19</strong>
        </div>

        <button
          type="button"
          className="topbar__icon-button"
          aria-label="Search"
        >
          <Search size={18} />
        </button>

        <button
          type="button"
          className="topbar__icon-button topbar__notification"
          aria-label="Notifications"
        >
          <Bell size={18} />
          <span className="topbar__notification-dot" />
        </button>

        <div className="topbar__profile">
          <div className="topbar__avatar">
            SB
          </div>

          <div className="topbar__profile-copy">
            <span className="topbar__profile-name">
              Security Analyst
            </span>

            <span className="topbar__profile-role">
              ADMIN
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

export default Topbar;