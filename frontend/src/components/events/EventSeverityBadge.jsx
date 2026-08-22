import {
  AlertOctagon,
  AlertTriangle,
  Info,
  ShieldAlert,
} from "lucide-react";

const SEVERITY_CONFIG = {
  CRITICAL: {
    label: "CRITICAL",
    icon: AlertOctagon,
    className: "critical",
  },

  HIGH: {
    label: "HIGH",
    icon: ShieldAlert,
    className: "high",
  },

  MEDIUM: {
    label: "MEDIUM",
    icon: AlertTriangle,
    className: "medium",
  },

  LOW: {
    label: "LOW",
    icon: Info,
    className: "low",
  },

  INFO: {
    label: "INFO",
    icon: Info,
    className: "info",
  },
};

function EventSeverityBadge({ severity = "INFO" }) {
  const normalizedSeverity = String(severity).toUpperCase();

  const config =
    SEVERITY_CONFIG[normalizedSeverity] ??
    SEVERITY_CONFIG.INFO;

  const Icon = config.icon;

  return (
    <span
      className={`event-severity event-severity--${config.className}`}
    >
      <Icon size={12} strokeWidth={2} />
      <span>{config.label}</span>
    </span>
  );
}

export default EventSeverityBadge;