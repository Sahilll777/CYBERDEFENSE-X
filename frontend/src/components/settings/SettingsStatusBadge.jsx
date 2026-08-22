import {
  AlertTriangle,
  CheckCircle2,
  CircleOff,
  LoaderCircle,
} from "lucide-react";

const STATUS_CONFIG = {
  OPERATIONAL: {
    label: "OPERATIONAL",
    icon: CheckCircle2,
    className: "operational",
  },
  WARNING: {
    label: "WARNING",
    icon: AlertTriangle,
    className: "warning",
  },
  OFFLINE: {
    label: "OFFLINE",
    icon: CircleOff,
    className: "offline",
  },
  SYNCING: {
    label: "SYNCING",
    icon: LoaderCircle,
    className: "syncing",
  },
};

function SettingsStatusBadge({ status = "OPERATIONAL" }) {
  const normalizedStatus = String(status).toUpperCase();

  const config =
    STATUS_CONFIG[normalizedStatus] ??
    STATUS_CONFIG.OPERATIONAL;

  const Icon = config.icon;

  return (
    <span
      className={`settings-status settings-status--${config.className}`}
    >
      <Icon size={13} strokeWidth={2} />
      <span>{config.label}</span>
    </span>
  );
}

export default SettingsStatusBadge;