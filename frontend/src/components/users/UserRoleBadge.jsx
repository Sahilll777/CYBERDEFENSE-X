import {
  Eye,
  KeyRound,
  ShieldCheck,
  UserCog,
  UserRound,
} from "lucide-react";

const ROLE_CONFIG = {
  ADMIN: {
    icon: ShieldCheck,
    label: "ADMIN",
    className: "admin",
  },
  "SOC ANALYST": {
    icon: UserRound,
    label: "SOC ANALYST",
    className: "analyst",
  },
  "SECURITY ENGINEER": {
    icon: UserCog,
    label: "SECURITY ENGINEER",
    className: "engineer",
  },
  "INCIDENT RESPONDER": {
    icon: KeyRound,
    label: "INCIDENT RESPONDER",
    className: "responder",
  },
  VIEWER: {
    icon: Eye,
    label: "VIEWER",
    className: "viewer",
  },
};

function UserRoleBadge({ role = "VIEWER" }) {
  const normalizedRole = String(role).toUpperCase();

  const config =
    ROLE_CONFIG[normalizedRole] ??
    ROLE_CONFIG.VIEWER;

  const Icon = config.icon;

  return (
    <span
      className={`user-role user-role--${config.className}`}
    >
      <Icon
        size={12}
        strokeWidth={1.9}
      />

      <span>{config.label}</span>
    </span>
  );
}

export default UserRoleBadge;