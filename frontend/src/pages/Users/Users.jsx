import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Filter,
  KeyRound,
  Mail,
  MoreHorizontal,
  Plus,
  Search,
  ShieldCheck,
  UserCog,
  UserRound,
  Users as UsersIcon,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";

import UserRoleBadge from "../../components/users/UserRoleBadge";

import "./Users.css";

const USERS = [
  {
    id: "USR-001",
    name: "Alex Morgan",
    username: "a.morgan",
    email: "a.morgan@cyberdefense.local",
    role: "ADMIN",
    department: "SECURITY OPERATIONS",
    status: "ACTIVE",
    lastLogin: "2 min ago",
    lastLoginDate: "20 Aug 2026 · 23:16 UTC",
    source: "10.24.2.15",
    mfa: true,
    sessions: 2,
    joined: "12 Jan 2026",
  },
  {
    id: "USR-002",
    name: "Sarah Chen",
    username: "s.chen",
    email: "s.chen@cyberdefense.local",
    role: "SOC ANALYST",
    department: "SECURITY OPERATIONS",
    status: "ACTIVE",
    lastLogin: "8 min ago",
    lastLoginDate: "20 Aug 2026 · 23:10 UTC",
    source: "10.24.18.42",
    mfa: true,
    sessions: 1,
    joined: "18 Feb 2026",
  },
  {
    id: "USR-003",
    name: "Daniel Brooks",
    username: "d.brooks",
    email: "d.brooks@cyberdefense.local",
    role: "SECURITY ENGINEER",
    department: "ENGINEERING",
    status: "ACTIVE",
    lastLogin: "21 min ago",
    lastLoginDate: "20 Aug 2026 · 22:57 UTC",
    source: "10.24.9.117",
    mfa: true,
    sessions: 1,
    joined: "03 Mar 2026",
  },
  {
    id: "USR-004",
    name: "Emily Carter",
    username: "e.carter",
    email: "e.carter@cyberdefense.local",
    role: "SOC ANALYST",
    department: "SECURITY OPERATIONS",
    status: "ACTIVE",
    lastLogin: "37 min ago",
    lastLoginDate: "20 Aug 2026 · 22:41 UTC",
    source: "10.24.6.31",
    mfa: true,
    sessions: 1,
    joined: "11 Apr 2026",
  },
  {
    id: "USR-005",
    name: "Michael Reed",
    username: "m.reed",
    email: "m.reed@cyberdefense.local",
    role: "VIEWER",
    department: "COMPLIANCE",
    status: "ACTIVE",
    lastLogin: "1 hr ago",
    lastLoginDate: "20 Aug 2026 · 22:19 UTC",
    source: "10.24.11.64",
    mfa: true,
    sessions: 0,
    joined: "27 Apr 2026",
  },
  {
    id: "USR-006",
    name: "Jessica Wilson",
    username: "j.wilson",
    email: "j.wilson@cyberdefense.local",
    role: "INCIDENT RESPONDER",
    department: "THREAT RESPONSE",
    status: "ACTIVE",
    lastLogin: "2 hr ago",
    lastLoginDate: "20 Aug 2026 · 21:24 UTC",
    source: "10.24.3.88",
    mfa: true,
    sessions: 1,
    joined: "06 May 2026",
  },
  {
    id: "USR-007",
    name: "Robert Davis",
    username: "r.davis",
    email: "r.davis@cyberdefense.local",
    role: "SOC ANALYST",
    department: "SECURITY OPERATIONS",
    status: "DISABLED",
    lastLogin: "3 days ago",
    lastLoginDate: "17 Aug 2026 · 18:42 UTC",
    source: "10.24.7.19",
    mfa: true,
    sessions: 0,
    joined: "22 May 2026",
  },
  {
    id: "USR-008",
    name: "Olivia Taylor",
    username: "o.taylor",
    email: "o.taylor@cyberdefense.local",
    role: "VIEWER",
    department: "AUDIT",
    status: "PENDING",
    lastLogin: "Never",
    lastLoginDate: "Invitation sent · 20 Aug 2026",
    source: "—",
    mfa: false,
    sessions: 0,
    joined: "20 Aug 2026",
  },
];

const ROLE_FILTERS = [
  "ALL ROLES",
  "ADMIN",
  "SOC ANALYST",
  "SECURITY ENGINEER",
  "INCIDENT RESPONDER",
  "VIEWER",
];

function MetricCard({
  icon: Icon,
  label,
  value,
  change,
  trend,
  tone,
}) {
  const TrendIcon =
    trend === "up" ? ArrowUpRight : ArrowDownRight;

  return (
    <article className={`users-metric users-metric--${tone}`}>
      <div className="users-metric__top">
        <span className="users-metric__icon">
          <Icon size={17} strokeWidth={1.9} />
        </span>

        <span className="users-metric__label">
          {label}
        </span>
      </div>

      <strong className="users-metric__value">
        {value}
      </strong>

      <div className="users-metric__footer">
        <span
          className={`users-metric__change users-metric__change--${trend}`}
        >
          <TrendIcon size={13} />
          {change}
        </span>

        <span>vs previous period</span>
      </div>
    </article>
  );
}

function UserStatus({ status }) {
  const normalized = status.toLowerCase();

  return (
    <span
      className={`user-status user-status--${normalized}`}
    >
      <span className="user-status__dot" />
      {status}
    </span>
  );
}

function UserRow({ user, onInspect, onToggle }) {
  return (
    <article className="user-row">
      <div className="user-row__identity">
        <div className="user-row__avatar">
          <UserRound size={17} />
        </div>

        <div className="user-row__name">
          <strong>{user.name}</strong>

          <span>
            @{user.username}
          </span>
        </div>
      </div>

      <div className="user-row__email">
        <Mail size={13} />
        {user.email}
      </div>

      <div className="user-row__role">
        <UserRoleBadge role={user.role} />
      </div>

      <div className="user-row__department">
        {user.department}
      </div>

      <div className="user-row__status">
        <UserStatus status={user.status} />
      </div>

      <div className="user-row__login">
        <span>{user.lastLogin}</span>

        <small>{user.source}</small>
      </div>

      <div className="user-row__actions">
        <button
          type="button"
          onClick={() => onInspect(user)}
          aria-label={`Inspect ${user.name}`}
        >
          <MoreHorizontal size={16} />
        </button>
      </div>

      <div className="user-row__desktop-controls">
        <button
          type="button"
          className="user-row__inspect"
          onClick={() => onInspect(user)}
        >
          Inspect
        </button>

        <button
          type="button"
          className="user-row__toggle"
          onClick={() => onToggle(user.id)}
        >
          {user.status === "ACTIVE"
            ? "Disable"
            : "Enable"}
        </button>
      </div>
    </article>
  );
}

function UserDetailsDrawer({ user, onClose, onToggle }) {
  if (!user) {
    return null;
  }

  return (
    <div
      className="users-drawer__overlay"
      role="presentation"
      onMouseDown={onClose}
    >
      <aside
        className="users-drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`${user.name} details`}
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <header className="users-drawer__header">
          <div>
            <span>USER ADMINISTRATION</span>

            <h2>User Profile</h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close user details"
          >
            <X size={18} />
          </button>
        </header>

        <div className="users-drawer__body">
          <div className="users-drawer__profile">
            <div className="users-drawer__avatar">
              <UserRound size={25} />
            </div>

            <div>
              <span>{user.id}</span>

              <strong>{user.name}</strong>

              <small>
                @{user.username}
              </small>
            </div>

            <UserStatus status={user.status} />
          </div>

          <div className="users-drawer__section">
            <span className="users-drawer__section-title">
              ACCESS CONTROL
            </span>

            <div className="users-drawer__grid">
              <div>
                <span>ROLE</span>
                <UserRoleBadge role={user.role} />
              </div>

              <div>
                <span>DEPARTMENT</span>
                <strong>{user.department}</strong>
              </div>

              <div>
                <span>MFA</span>

                <strong className="users-drawer__mfa">
                  <CheckCircle2 size={13} />
                  {user.mfa
                    ? "ENABLED"
                    : "NOT CONFIGURED"}
                </strong>
              </div>

              <div>
                <span>ACTIVE SESSIONS</span>
                <strong>{user.sessions}</strong>
              </div>
            </div>
          </div>

          <div className="users-drawer__section">
            <span className="users-drawer__section-title">
              ACCOUNT ACTIVITY
            </span>

            <div className="users-drawer__activity">
              <div>
                <Clock3 size={15} />

                <div>
                  <span>LAST LOGIN</span>
                  <strong>
                    {user.lastLoginDate}
                  </strong>
                </div>
              </div>

              <div>
                <Activity size={15} />

                <div>
                  <span>SOURCE ADDRESS</span>
                  <strong>{user.source}</strong>
                </div>
              </div>

              <div>
                <UserCog size={15} />

                <div>
                  <span>ACCOUNT CREATED</span>
                  <strong>{user.joined}</strong>
                </div>
              </div>
            </div>
          </div>

          <div className="users-drawer__section">
            <span className="users-drawer__section-title">
              CONTACT
            </span>

            <div className="users-drawer__contact">
              <Mail size={15} />
              <span>{user.email}</span>
            </div>
          </div>
        </div>

        <footer className="users-drawer__footer">
          <button
            type="button"
            onClick={onClose}
          >
            Close
          </button>

          <button
            type="button"
            onClick={() => {
              onToggle(user.id);
              onClose();
            }}
          >
            {user.status === "ACTIVE"
              ? "Disable Account"
              : "Enable Account"}
          </button>
        </footer>
      </aside>
    </div>
  );
}

function Users() {
  const [activeRole, setActiveRole] =
    useState("ALL ROLES");

  const [activeStatus, setActiveStatus] =
    useState("ALL");

  const [searchQuery, setSearchQuery] =
    useState("");

  const [selectedUser, setSelectedUser] =
    useState(null);

  const [userStates, setUserStates] =
    useState(
      Object.fromEntries(
        USERS.map((user) => [
          user.id,
          user.status,
        ]),
      ),
    );

  const filteredUsers = useMemo(() => {
    const query = searchQuery
      .trim()
      .toLowerCase();

    return USERS.filter((user) => {
      const roleMatches =
        activeRole === "ALL ROLES" ||
        user.role === activeRole;

      const currentStatus =
        userStates[user.id] ?? user.status;

      const statusMatches =
        activeStatus === "ALL" ||
        currentStatus === activeStatus;

      if (!roleMatches || !statusMatches) {
        return false;
      }

      if (!query) {
        return true;
      }

      return [
        user.id,
        user.name,
        user.username,
        user.email,
        user.role,
        user.department,
        user.source,
      ].some((value) =>
        String(value)
          .toLowerCase()
          .includes(query),
      );
    });
  }, [
    activeRole,
    activeStatus,
    searchQuery,
    userStates,
  ]);

  const metrics = useMemo(() => {
    const active = USERS.filter(
      (user) =>
        userStates[user.id] === "ACTIVE",
    ).length;

    const pending = USERS.filter(
      (user) =>
        userStates[user.id] === "PENDING",
    ).length;

    const mfaEnabled = USERS.filter(
      (user) => user.mfa,
    ).length;

    return [
      {
        label: "Total Users",
        value: String(USERS.length).padStart(
          2,
          "0",
        ),
        change: "+2",
        trend: "up",
        tone: "cyan",
        icon: UsersIcon,
      },
      {
        label: "Active Accounts",
        value: String(active).padStart(2, "0"),
        change: "+1",
        trend: "up",
        tone: "success",
        icon: ShieldCheck,
      },
      {
        label: "MFA Coverage",
        value: `${Math.round(
          (mfaEnabled / USERS.length) * 100,
        )}%`,
        change: "+4.2%",
        trend: "up",
        tone: "success",
        icon: KeyRound,
      },
      {
        label: "Pending Access",
        value: String(pending).padStart(2, "0"),
        change: "-1",
        trend: "down",
        tone: "warning",
        icon: Clock3,
      },
    ];
  }, [userStates]);

  const toggleUser = (userId) => {
    setUserStates((current) => {
      const currentStatus = current[userId];

      return {
        ...current,
        [userId]:
          currentStatus === "ACTIVE"
            ? "DISABLED"
            : "ACTIVE",
      };
    });
  };

  const clearFilters = () => {
    setSearchQuery("");
    setActiveRole("ALL ROLES");
    setActiveStatus("ALL");
  };

  return (
    <div className="users-page">
      <header className="users-page__header">
        <div>
          <div className="users-breadcrumb">
            CYBERDEFENSE-X
            <span>/</span>
            SOC
            <span>/</span>
            ADMINISTRATION
            <span>/</span>
            USERS
          </div>

          <div className="users-title-row">
            <div>
              <div className="users-eyebrow">
                <UserCog size={13} />
                IDENTITY & ACCESS MANAGEMENT
              </div>

              <h1>User Administration</h1>

              <p>
                Manage security operations users,
                roles, access privileges and account
                security controls.
              </p>
            </div>

            <div className="users-security-status">
              <span className="users-security-status__pulse" />

              <div>
                <strong>
                  ACCESS CONTROL ONLINE
                </strong>

                <span>
                  RBAC POLICY ENFORCED
                </span>
              </div>

              <ShieldCheck size={17} />
            </div>
          </div>
        </div>
      </header>

      <section className="users-metrics">
        {metrics.map((metric) => (
          <MetricCard
            key={metric.label}
            {...metric}
          />
        ))}
      </section>

      <section className="users-directory">
        <div className="users-directory__header">
          <div>
            <span className="users-section-kicker">
              <UsersIcon size={13} />
              USER DIRECTORY
            </span>

            <h2>Security Operations Users</h2>

            <p>
              Authorized personnel and role
              assignments across the defense node.
            </p>
          </div>

          <button
            type="button"
            className="users-add-button"
            onClick={() =>
              window.alert(
                "User creation workflow will be connected to the backend in the next phase.",
              )
            }
          >
            <Plus size={15} />
            Add User
          </button>
        </div>

        <div className="users-controls">
          <div className="users-search">
            <Search size={16} />

            <input
              type="search"
              value={searchQuery}
              onChange={(event) =>
                setSearchQuery(
                  event.target.value,
                )
              }
              placeholder="Search users, roles, departments..."
              aria-label="Search users"
            />

            {searchQuery && (
              <button
                type="button"
                onClick={() =>
                  setSearchQuery("")
                }
                aria-label="Clear search"
              >
                <X size={14} />
              </button>
            )}
          </div>

          <div className="users-role-filter">
            <Filter size={14} />

            <select
              value={activeRole}
              onChange={(event) =>
                setActiveRole(
                  event.target.value,
                )
              }
              aria-label="Filter by role"
            >
              {ROLE_FILTERS.map((role) => (
                <option
                  key={role}
                  value={role}
                >
                  {role}
                </option>
              ))}
            </select>

            <ChevronDown size={14} />
          </div>

          <div className="users-status-filter">
            {[
              "ALL",
              "ACTIVE",
              "DISABLED",
              "PENDING",
            ].map((status) => (
              <button
                type="button"
                key={status}
                className={
                  activeStatus === status
                    ? "users-status-filter__button users-status-filter__button--active"
                    : "users-status-filter__button"
                }
                onClick={() =>
                  setActiveStatus(status)
                }
              >
                {status}
              </button>
            ))}
          </div>
        </div>

        <div className="users-directory__summary">
          <span>
            {filteredUsers.length
              .toString()
              .padStart(2, "0")}
          </span>

          <small>
            USERS DISPLAYED
          </small>

          {(searchQuery ||
            activeRole !== "ALL ROLES" ||
            activeStatus !== "ALL") && (
            <button
              type="button"
              onClick={clearFilters}
            >
              Clear filters
            </button>
          )}
        </div>

        <div className="users-table">
          <div className="users-table__header">
            <span>USER</span>
            <span>EMAIL</span>
            <span>ROLE</span>
            <span>DEPARTMENT</span>
            <span>STATUS</span>
            <span>LAST ACTIVITY</span>
            <span />
          </div>

          <div className="users-table__body">
            {filteredUsers.length > 0 ? (
              filteredUsers.map((user) => (
                <UserRow
                  key={user.id}
                  user={{
                    ...user,
                    status:
                      userStates[user.id],
                  }}
                  onInspect={setSelectedUser}
                  onToggle={toggleUser}
                />
              ))
            ) : (
              <div className="users-empty">
                <Search size={28} />

                <h3>
                  No users found
                </h3>

                <p>
                  No accounts match the
                  current search or filters.
                </p>

                <button
                  type="button"
                  onClick={clearFilters}
                >
                  Clear Filters
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      <footer className="users-footer">
        <div>
          <span className="users-footer__pulse" />
          IDENTITY SERVICE ONLINE
        </div>

        <span>
          RBAC <strong>ENFORCED</strong>
        </span>

        <span>
          MFA POLICY <strong>REQUIRED</strong>
        </span>

        <span>
          DIRECTORY <strong>SYNCED</strong>
        </span>
      </footer>

      <UserDetailsDrawer
        user={
          selectedUser
            ? {
                ...selectedUser,
                status:
                  userStates[
                    selectedUser.id
                  ],
              }
            : null
        }
        onClose={() =>
          setSelectedUser(null)
        }
        onToggle={toggleUser}
      />
    </div>
  );
}

export default Users;