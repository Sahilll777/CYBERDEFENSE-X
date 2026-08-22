import {
  CheckCircle2,
  PauseCircle,
  PlayCircle,
  XCircle,
} from "lucide-react";

const statusConfig = {
  ACTIVE: {
    label: "ACTIVE",
    icon: PlayCircle,
    className: "active",
  },
  PAUSED: {
    label: "PAUSED",
    icon: PauseCircle,
    className: "paused",
  },
  SUCCESS: {
    label: "SUCCESS",
    icon: CheckCircle2,
    className: "success",
  },
  FAILED: {
    label: "FAILED",
    icon: XCircle,
    className: "failed",
  },
};

function PlaybookStatusBadge({ status = "PAUSED" }) {
  const normalizedStatus = String(status).toUpperCase();

  const config =
    statusConfig[normalizedStatus] ?? statusConfig.PAUSED;

  const Icon = config.icon;

  return (
    <span
      className={`playbook-status playbook-status--${config.className}`}
    >
      <Icon size={13} strokeWidth={2} />
      <span>{config.label}</span>
    </span>
  );
}

export default PlaybookStatusBadge;