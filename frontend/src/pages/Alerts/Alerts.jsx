import {
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  Ban,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Crosshair,
  ExternalLink,
  FileSearch,
  Filter,
  Flame,
  Globe2,
  LockKeyhole,
  Search,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Target,
  X,
  Zap,
} from "lucide-react";
import { useMemo, useState } from "react";

import "./Alerts.css";

const alertData = [
  {
    id: "ALT-2048",
    title: "Multiple failed authentication attempts",
    description:
      "Repeated authentication failures detected against a privileged account.",
    source: "10.24.18.42",
    destination: "AD-SRV-01",
    technique: "T1110",
    tactic: "Credential Access",
    severity: "CRITICAL",
    status: "OPEN",
    timestamp: "23:18:42",
    age: "8m",
    rule: "AUTH-BRUTE-001",
  },
  {
    id: "ALT-2047",
    title: "Encoded PowerShell execution",
    description:
      "Encoded PowerShell command execution detected on an internal endpoint.",
    source: "10.24.9.117",
    destination: "WS-117",
    technique: "T1059.001",
    tactic: "Execution",
    severity: "HIGH",
    status: "INVESTIGATING",
    timestamp: "23:16:08",
    age: "14m",
    rule: "PS-ENCODED-003",
  },
  {
    id: "ALT-2046",
    title: "Outbound connection matched IOC",
    description:
      "Outbound network traffic matched a known malicious indicator.",
    source: "10.24.6.31",
    destination: "185.220.101.44",
    technique: "T1071.001",
    tactic: "Command and Control",
    severity: "HIGH",
    status: "OPEN",
    timestamp: "23:14:31",
    age: "21m",
    rule: "IOC-NET-007",
  },
  {
    id: "ALT-2045",
    title: "Privilege escalation detected",
    description:
      "Unexpected privilege escalation activity detected on a monitored host.",
    source: "10.24.3.88",
    destination: "LIN-SRV-04",
    technique: "T1548",
    tactic: "Privilege Escalation",
    severity: "MEDIUM",
    status: "OPEN",
    timestamp: "23:11:57",
    age: "37m",
    rule: "PRIV-ESC-002",
  },
  {
    id: "ALT-2044",
    title: "Sensitive configuration file accessed",
    description:
      "Sensitive configuration data was accessed outside the expected process.",
    source: "10.24.3.88",
    destination: "LIN-SRV-04",
    technique: "T1005",
    tactic: "Collection",
    severity: "MEDIUM",
    status: "ACKNOWLEDGED",
    timestamp: "23:08:13",
    age: "41m",
    rule: "FILE-ACCESS-009",
  },
  {
    id: "ALT-2043",
    title: "Suspicious service creation",
    description:
      "A new system service was created by a non-standard process.",
    source: "10.24.12.76",
    destination: "WS-076",
    technique: "T1543.003",
    tactic: "Persistence",
    severity: "HIGH",
    status: "INVESTIGATING",
    timestamp: "23:04:52",
    age: "46m",
    rule: "SERVICE-NEW-004",
  },
  {
    id: "ALT-2042",
    title: "Unusual DNS query pattern",
    description:
      "High-frequency DNS requests suggest possible command-and-control activity.",
    source: "10.24.14.21",
    destination: "DNS-01",
    technique: "T1071.004",
    tactic: "Command and Control",
    severity: "LOW",
    status: "ACKNOWLEDGED",
    timestamp: "22:59:37",
    age: "52m",
    rule: "DNS-ANOM-005",
  },
];

const severityOptions = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

const statusOptions = [
  "ALL",
  "OPEN",
  "INVESTIGATING",
  "ACKNOWLEDGED",
  "RESOLVED",
];

const severityMeta = {
  CRITICAL: {
    icon: Siren,
    label: "Critical",
  },
  HIGH: {
    icon: ShieldAlert,
    label: "High",
  },
  MEDIUM: {
    icon: AlertTriangle,
    label: "Medium",
  },
  LOW: {
    icon: AlertCircle,
    label: "Low",
  },
};

const statusMeta = {
  OPEN: {
    icon: Flame,
    label: "Open",
  },
  INVESTIGATING: {
    icon: Search,
    label: "Investigating",
  },
  ACKNOWLEDGED: {
    icon: CheckCircle2,
    label: "Acknowledged",
  },
  RESOLVED: {
    icon: ShieldCheck,
    label: "Resolved",
  },
};

function SeverityBadge({ severity }) {
  const meta = severityMeta[severity] ?? severityMeta.LOW;
  const Icon = meta.icon;

  return (
    <span
      className={`alerts-severity alerts-severity--${severity.toLowerCase()}`}
    >
      <Icon size={12} />
      {meta.label}
    </span>
  );
}

function StatusBadge({ status }) {
  const meta = statusMeta[status] ?? statusMeta.OPEN;
  const Icon = meta.icon;

  return (
    <span
      className={`alerts-status alerts-status--${status.toLowerCase()}`}
    >
      <Icon size={12} />
      {meta.label}
    </span>
  );
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  description,
  tone,
}) {
  return (
    <article className={`alerts-summary alerts-summary--${tone}`}>
      <div className="alerts-summary__top">
        <div className="alerts-summary__icon">
          <Icon size={18} />
        </div>

        <span>{label}</span>
      </div>

      <strong className="alerts-summary__value">{value}</strong>

      <div className="alerts-summary__description">
        {description}
      </div>
    </article>
  );
}

function AlertRow({ alert, selected, onSelect }) {
  return (
    <article
      className={[
        "alerts-row",
        selected ? "alerts-row--selected" : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <div className="alerts-row__select">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onSelect(alert.id)}
          aria-label={`Select ${alert.id}`}
        />
      </div>

      <div className="alerts-row__alert">
        <div className="alerts-row__identity">
          <span className="alerts-row__id">{alert.id}</span>

          <span className="alerts-row__rule">
            {alert.rule}
          </span>
        </div>

        <strong>{alert.title}</strong>

        <p>{alert.description}</p>
      </div>

      <div className="alerts-row__severity">
        <SeverityBadge severity={alert.severity} />
      </div>

      <div className="alerts-row__status">
        <StatusBadge status={alert.status} />
      </div>

      <div className="alerts-row__source">
        <span>SOURCE</span>
        <strong>{alert.source}</strong>
        <small>{alert.destination}</small>
      </div>

      <div className="alerts-row__technique">
        <strong>{alert.technique}</strong>
        <span>{alert.tactic}</span>
      </div>

      <div className="alerts-row__time">
        <div>
          <Clock3 size={13} />
          <strong>{alert.age}</strong>
        </div>

        <span>{alert.timestamp}</span>
      </div>

      <button
        type="button"
        className="alerts-row__open"
        aria-label={`Open ${alert.id}`}
      >
        <ArrowUpRight size={16} />
      </button>
    </article>
  );
}

function Alerts() {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedAlerts, setSelectedAlerts] = useState([]);

  const filteredAlerts = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    return alertData.filter((alert) => {
      const searchableContent = [
        alert.id,
        alert.title,
        alert.description,
        alert.source,
        alert.destination,
        alert.technique,
        alert.tactic,
        alert.rule,
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        !query || searchableContent.includes(query);

      const matchesSeverity =
        severityFilter === "ALL" ||
        alert.severity === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" ||
        alert.status === statusFilter;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus
      );
    });
  }, [searchQuery, severityFilter, statusFilter]);

  const toggleAlertSelection = (alertId) => {
    setSelectedAlerts((current) =>
      current.includes(alertId)
        ? current.filter((id) => id !== alertId)
        : [...current, alertId],
    );
  };

  const toggleAllVisibleAlerts = () => {
    const visibleIds = filteredAlerts.map((alert) => alert.id);

    const allSelected = visibleIds.every((id) =>
      selectedAlerts.includes(id),
    );

    if (allSelected) {
      setSelectedAlerts((current) =>
        current.filter((id) => !visibleIds.includes(id)),
      );
      return;
    }

    setSelectedAlerts((current) => [
      ...new Set([...current, ...visibleIds]),
    ]);
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSeverityFilter("ALL");
    setStatusFilter("ALL");
  };

  const allVisibleSelected =
    filteredAlerts.length > 0 &&
    filteredAlerts.every((alert) =>
      selectedAlerts.includes(alert.id),
    );

  return (
    <div className="alerts-page">
      <header className="alerts-page__header">
        <div className="alerts-breadcrumb">
          CYBERDEFENSE-X
          <span>/</span>
          SOC
          <span>/</span>
          ALERTS
        </div>

        <div className="alerts-page__title-row">
          <div>
            <div className="alerts-eyebrow">
              <ShieldAlert size={13} />
              SECURITY ALERT MANAGEMENT
            </div>

            <h1>Security Alerts</h1>

            <p>
              Investigate, triage and manage detections generated
              by the defense engine.
            </p>
          </div>

          <div className="alerts-operational">
            <span className="alerts-operational__dot" />

            <div>
              <span>ALERT PIPELINE</span>
              <strong>OPERATIONAL</strong>
            </div>
          </div>
        </div>
      </header>

      <section className="alerts-summary-grid">
        <SummaryCard
          icon={Siren}
          label="Critical Alerts"
          value="07"
          description="Require immediate attention"
          tone="critical"
        />

        <SummaryCard
          icon={ShieldAlert}
          label="High Severity"
          value="18"
          description="Active high-risk detections"
          tone="high"
        />

        <SummaryCard
          icon={Target}
          label="Under Investigation"
          value="04"
          description="Currently assigned to analysts"
          tone="investigating"
        />

        <SummaryCard
          icon={CheckCircle2}
          label="Resolved Today"
          value="31"
          description="Successfully closed"
          tone="success"
        />
      </section>

      <section className="alerts-intelligence">
        <div className="alerts-intelligence__item">
          <div className="alerts-intelligence__icon">
            <Crosshair size={16} />
          </div>

          <div>
            <span>DETECTION COVERAGE</span>
            <strong>98.7%</strong>
          </div>
        </div>

        <div className="alerts-intelligence__item">
          <div className="alerts-intelligence__icon">
            <Zap size={16} />
          </div>

          <div>
            <span>MEAN TIME TO DETECT</span>
            <strong>42 sec</strong>
          </div>
        </div>

        <div className="alerts-intelligence__item">
          <div className="alerts-intelligence__icon">
            <LockKeyhole size={16} />
          </div>

          <div>
            <span>FALSE POSITIVE RATE</span>
            <strong>1.8%</strong>
          </div>
        </div>

        <div className="alerts-intelligence__item">
          <div className="alerts-intelligence__icon">
            <Globe2 size={16} />
          </div>

          <div>
            <span>EVENTS ANALYZED</span>
            <strong>18.4K/hr</strong>
          </div>
        </div>
      </section>

      <section className="alerts-panel">
        <div className="alerts-panel__header">
          <div>
            <div className="alerts-panel__eyebrow">
              <FileSearch size={13} />
              DETECTION STREAM
            </div>

            <h2>Alert Queue</h2>

            <p>
              Real-time detections requiring analyst review.
            </p>
          </div>

          <div className="alerts-live">
            <span />
            LIVE INGESTION
          </div>
        </div>

        <div className="alerts-toolbar">
          <div className="alerts-search">
            <Search size={16} />

            <input
              type="search"
              placeholder="Search alerts, sources, techniques..."
              value={searchQuery}
              onChange={(event) =>
                setSearchQuery(event.target.value)
              }
            />

            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                aria-label="Clear search"
              >
                <X size={14} />
              </button>
            )}
          </div>

          <label className="alerts-filter">
            <Filter size={14} />

            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
            >
              {severityOptions.map((option) => (
                <option key={option} value={option}>
                  {option === "ALL"
                    ? "All severities"
                    : option}
                </option>
              ))}
            </select>

            <ChevronDown size={13} />
          </label>

          <label className="alerts-filter">
            <ShieldCheck size={14} />

            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value)
              }
            >
              {statusOptions.map((option) => (
                <option key={option} value={option}>
                  {option === "ALL"
                    ? "All statuses"
                    : option}
                </option>
              ))}
            </select>

            <ChevronDown size={13} />
          </label>

          {(searchQuery ||
            severityFilter !== "ALL" ||
            statusFilter !== "ALL") && (
            <button
              type="button"
              className="alerts-clear"
              onClick={clearFilters}
            >
              <X size={14} />
              Clear
            </button>
          )}
        </div>

        {selectedAlerts.length > 0 && (
          <div className="alerts-bulk">
            <div>
              <strong>{selectedAlerts.length}</strong>
              <span>selected</span>
            </div>

            <div className="alerts-bulk__actions">
              <button type="button">
                <CheckCircle2 size={14} />
                Acknowledge
              </button>

              <button type="button">
                <Ban size={14} />
                Resolve
              </button>

              <button
                type="button"
                onClick={() => setSelectedAlerts([])}
              >
                <X size={14} />
                Clear
              </button>
            </div>
          </div>
        )}

        <div className="alerts-table">
          <div className="alerts-table__header">
            <div>
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={toggleAllVisibleAlerts}
                aria-label="Select all alerts"
              />
            </div>

            <span>ALERT</span>
            <span>SEVERITY</span>
            <span>STATUS</span>
            <span>SOURCE</span>
            <span>TECHNIQUE</span>
            <span>AGE</span>
            <span />
          </div>

          <div className="alerts-table__body">
            {filteredAlerts.length > 0 ? (
              filteredAlerts.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  selected={selectedAlerts.includes(alert.id)}
                  onSelect={toggleAlertSelection}
                />
              ))
            ) : (
              <div className="alerts-empty">
                <div className="alerts-empty__icon">
                  <Search size={22} />
                </div>

                <h3>No alerts found</h3>

                <p>
                  No detections match the current search and
                  filters.
                </p>

                <button
                  type="button"
                  onClick={clearFilters}
                >
                  Reset filters
                </button>
              </div>
            )}
          </div>
        </div>

        <footer className="alerts-panel__footer">
          <span>
            SHOWING <strong>{filteredAlerts.length}</strong> OF{" "}
            <strong>{alertData.length}</strong> ALERTS
          </span>

          <span>
            <i />
            TELEMETRY SYNCHRONIZED
          </span>
        </footer>
      </section>

      <footer className="alerts-page__footer">
        <span>
          <ShieldCheck size={13} />
          CYBERDEFENSE-X ALERT MANAGEMENT
        </span>

        <span>
          <ExternalLink size={13} />
          DEFENSE NODE / LOCAL SECURE
        </span>

        <span>REFRESH INTERVAL &lt; 5 SEC</span>
      </footer>
    </div>
  );
}

export default Alerts;