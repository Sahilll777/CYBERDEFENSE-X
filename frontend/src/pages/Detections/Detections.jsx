import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Code2,
  Filter,
  Gauge,
  Layers3,
  MoreHorizontal,
  Play,
  Power,
  Search,
  ShieldAlert,
  ShieldCheck,
  Target,
  TerminalSquare,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";

import "./Detections.css";

const detectionRules = [
  {
    id: "DET-0048",
    name: "Multiple Failed Authentication Attempts",
    description:
      "Detects repeated authentication failures against privileged or sensitive accounts.",
    severity: "CRITICAL",
    status: "ACTIVE",
    technique: "T1110",
    tactic: "Credential Access",
    source: "Authentication",
    triggers: 1284,
    lastTriggered: "2m ago",
    version: "v3.2",
    coverage: 98,
    owner: "SOC Core",
  },
  {
    id: "DET-0047",
    name: "Encoded PowerShell Execution",
    description:
      "Identifies encoded or obfuscated PowerShell commands executed on monitored endpoints.",
    severity: "HIGH",
    status: "ACTIVE",
    technique: "T1059.001",
    tactic: "Execution",
    source: "Endpoint",
    triggers: 642,
    lastTriggered: "8m ago",
    version: "v2.8",
    coverage: 94,
    owner: "Detection Team",
  },
  {
    id: "DET-0046",
    name: "Outbound Connection Matched IOC",
    description:
      "Detects outbound network connections matching known malicious indicators of compromise.",
    severity: "HIGH",
    status: "ACTIVE",
    technique: "T1071.001",
    tactic: "Command and Control",
    source: "Network",
    triggers: 391,
    lastTriggered: "14m ago",
    version: "v4.1",
    coverage: 96,
    owner: "Threat Intel",
  },
  {
    id: "DET-0045",
    name: "Suspicious Privilege Escalation",
    description:
      "Identifies unexpected privilege elevation activity from non-administrative accounts.",
    severity: "MEDIUM",
    status: "ACTIVE",
    technique: "T1548",
    tactic: "Privilege Escalation",
    source: "Endpoint",
    triggers: 187,
    lastTriggered: "21m ago",
    version: "v2.4",
    coverage: 89,
    owner: "Detection Team",
  },
  {
    id: "DET-0044",
    name: "Sensitive Configuration File Access",
    description:
      "Detects unauthorized access to protected configuration and credential files.",
    severity: "MEDIUM",
    status: "ACTIVE",
    technique: "T1552.001",
    tactic: "Credential Access",
    source: "File System",
    triggers: 96,
    lastTriggered: "37m ago",
    version: "v1.9",
    coverage: 91,
    owner: "SOC Core",
  },
  {
    id: "DET-0043",
    name: "Unusual Process Creation",
    description:
      "Flags process creation patterns that deviate from the established endpoint baseline.",
    severity: "LOW",
    status: "ACTIVE",
    technique: "T1059",
    tactic: "Execution",
    source: "Endpoint",
    triggers: 74,
    lastTriggered: "42m ago",
    version: "v3.0",
    coverage: 84,
    owner: "Detection Team",
  },
  {
    id: "DET-0042",
    name: "Legacy SMB Authentication",
    description:
      "Monitors legacy SMB authentication patterns that may indicate lateral movement.",
    severity: "HIGH",
    status: "DISABLED",
    technique: "T1021.002",
    tactic: "Lateral Movement",
    source: "Network",
    triggers: 0,
    lastTriggered: "2h ago",
    version: "v1.7",
    coverage: 72,
    owner: "SOC Core",
  },
  {
    id: "DET-0041",
    name: "Abnormal Service Account Activity",
    description:
      "Detects service accounts performing interactive or unusual administrative operations.",
    severity: "MEDIUM",
    status: "ACTIVE",
    technique: "T1078",
    tactic: "Persistence",
    source: "Identity",
    triggers: 43,
    lastTriggered: "1h ago",
    version: "v2.1",
    coverage: 87,
    owner: "Identity Security",
  },
];

const severityOptions = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const statusOptions = ["ALL", "ACTIVE", "DISABLED"];

function SeverityBadge({ severity }) {
  return (
    <span
      className={`detection-severity detection-severity--${severity.toLowerCase()}`}
    >
      <span className="detection-severity__dot" />
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const isActive = status === "ACTIVE";

  return (
    <span
      className={`detection-status ${
        isActive
          ? "detection-status--active"
          : "detection-status--disabled"
      }`}
    >
      {isActive ? (
        <CheckCircle2 size={13} />
      ) : (
        <XCircle size={13} />
      )}
      {status}
    </span>
  );
}

function MetricCard({ icon: Icon, label, value, change, trend, tone }) {
  const TrendIcon =
    trend === "down" ? ArrowDownRight : ArrowUpRight;

  return (
    <article
      className={`detection-metric detection-metric--${tone}`}
    >
      <div className="detection-metric__top">
        <div className="detection-metric__icon">
          <Icon size={18} strokeWidth={1.8} />
        </div>

        <span>{label}</span>
      </div>

      <strong>{value}</strong>

      <div className="detection-metric__footer">
        <span
          className={`detection-metric__change detection-metric__change--${trend}`}
        >
          <TrendIcon size={13} />
          {change}
        </span>

        <span>vs previous period</span>
      </div>
    </article>
  );
}

function RuleRow({ rule, onSelect }) {
  return (
    <article
      className={`detection-rule ${
        rule.status === "DISABLED"
          ? "detection-rule--disabled"
          : ""
      }`}
      onClick={() => onSelect(rule)}
    >
      <div className="detection-rule__identity">
        <div className="detection-rule__icon">
          <Target size={17} />
        </div>

        <div className="detection-rule__name">
          <div className="detection-rule__name-line">
            <strong>{rule.name}</strong>

            <span className="detection-rule__id">
              {rule.id}
            </span>
          </div>

          <p>{rule.description}</p>

          <div className="detection-rule__meta">
            <span>
              <Code2 size={12} />
              {rule.version}
            </span>

            <span>
              <TerminalSquare size={12} />
              {rule.source}
            </span>

            <span>
              <Layers3 size={12} />
              {rule.tactic}
            </span>
          </div>
        </div>
      </div>

      <div className="detection-rule__technique">
        <span>MITRE ATT&amp;CK</span>
        <strong>{rule.technique}</strong>
      </div>

      <div className="detection-rule__severity">
        <SeverityBadge severity={rule.severity} />
      </div>

      <div className="detection-rule__status">
        <StatusBadge status={rule.status} />
      </div>

      <div className="detection-rule__triggers">
        <strong>{rule.triggers.toLocaleString()}</strong>
        <span>matches</span>
      </div>

      <div className="detection-rule__last">
        <Clock3 size={13} />
        <span>{rule.lastTriggered}</span>
      </div>

      <button
        type="button"
        className="detection-rule__menu"
        aria-label={`Actions for ${rule.name}`}
        onClick={(event) => event.stopPropagation()}
      >
        <MoreHorizontal size={17} />
      </button>
    </article>
  );
}

function RuleDetails({ rule, onClose }) {
  if (!rule) {
    return null;
  }

  return (
    <div className="detection-drawer-backdrop" onClick={onClose}>
      <aside
        className="detection-drawer"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="detection-drawer__header">
          <div>
            <span className="detection-eyebrow">
              <Target size={13} />
              RULE INSPECTOR
            </span>

            <h2>{rule.name}</h2>

            <span className="detection-drawer__id">
              {rule.id} · {rule.version}
            </span>
          </div>

          <button
            type="button"
            className="detection-drawer__close"
            onClick={onClose}
            aria-label="Close rule inspector"
          >
            ×
          </button>
        </header>

        <div className="detection-drawer__body">
          <div className="detection-drawer__badges">
            <SeverityBadge severity={rule.severity} />
            <StatusBadge status={rule.status} />
          </div>

          <section className="detection-detail-block">
            <span>DESCRIPTION</span>
            <p>{rule.description}</p>
          </section>

          <section className="detection-detail-grid">
            <div>
              <span>MITRE TECHNIQUE</span>
              <strong>{rule.technique}</strong>
            </div>

            <div>
              <span>TACTIC</span>
              <strong>{rule.tactic}</strong>
            </div>

            <div>
              <span>SOURCE</span>
              <strong>{rule.source}</strong>
            </div>

            <div>
              <span>OWNER</span>
              <strong>{rule.owner}</strong>
            </div>
          </section>

          <section className="detection-detail-block">
            <div className="detection-detail-block__heading">
              <span>RULE PERFORMANCE</span>
              <strong>{rule.coverage}% coverage</strong>
            </div>

            <div className="detection-performance">
              <span
                style={{
                  width: `${rule.coverage}%`,
                }}
              />
            </div>
          </section>

          <section className="detection-detail-stats">
            <div>
              <span>TOTAL MATCHES</span>
              <strong>
                {rule.triggers.toLocaleString()}
              </strong>
            </div>

            <div>
              <span>LAST TRIGGERED</span>
              <strong>{rule.lastTriggered}</strong>
            </div>
          </section>

          <div className="detection-drawer__actions">
            <button type="button">
              <Play size={15} />
              Test Rule
            </button>

            <button type="button">
              <Power size={15} />
              {rule.status === "ACTIVE"
                ? "Disable Rule"
                : "Enable Rule"}
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
}

function Detections() {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedRule, setSelectedRule] = useState(null);

  const filteredRules = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();

    return detectionRules.filter((rule) => {
      const matchesSearch =
        !normalizedSearch ||
        rule.name.toLowerCase().includes(normalizedSearch) ||
        rule.id.toLowerCase().includes(normalizedSearch) ||
        rule.technique.toLowerCase().includes(normalizedSearch) ||
        rule.tactic.toLowerCase().includes(normalizedSearch) ||
        rule.source.toLowerCase().includes(normalizedSearch);

      const matchesSeverity =
        severityFilter === "ALL" ||
        rule.severity === severityFilter;

      const matchesStatus =
        statusFilter === "ALL" ||
        rule.status === statusFilter;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus
      );
    });
  }, [searchTerm, severityFilter, statusFilter]);

  return (
    <div className="detections-page">
      <header className="detections-page__header">
        <div>
          <div className="detection-breadcrumb">
            CYBERDEFENSE-X
            <span>/</span>
            SOC
            <span>/</span>
            DETECTION ENGINE
          </div>

          <div className="detections-title-row">
            <div>
              <span className="detection-eyebrow">
                <ShieldCheck size={13} />
                DETECTION ENGINEERING
              </span>

              <h1>Detection Rules</h1>

              <p>
                Create, tune and monitor the rules powering
                the CYBERDEFENSE-X detection engine.
              </p>
            </div>

            <div className="detections-engine-status">
              <span className="detections-engine-status__icon">
                <Gauge size={18} />
              </span>

              <div>
                <span>DETECTION ENGINE</span>
                <strong>
                  <i />
                  OPERATIONAL
                </strong>
              </div>
            </div>
          </div>
        </div>
      </header>

      <section className="detection-metrics">
        <MetricCard
          icon={ShieldCheck}
          label="Active Rules"
          value="42"
          change="+3"
          trend="up"
          tone="success"
        />

        <MetricCard
          icon={AlertTriangle}
          label="Critical Rules"
          value="08"
          change="+1"
          trend="up"
          tone="critical"
        />

        <MetricCard
          icon={Power}
          label="Disabled Rules"
          value="05"
          change="-2"
          trend="down"
          tone="warning"
        />

        <MetricCard
          icon={Activity}
          label="Detections / Hour"
          value="18.4K"
          change="+12.8%"
          trend="up"
          tone="cyan"
        />
      </section>

      <section className="detection-workspace">
        <div className="detection-workspace__header">
          <div>
            <span className="detection-eyebrow">
              <Target size={13} />
              RULE REGISTRY
            </span>

            <h2>Detection Rule Library</h2>

            <p>
              {filteredRules.length} of{" "}
              {detectionRules.length} rules displayed
            </p>
          </div>

          <div className="detection-workspace__summary">
            <span>
              <i className="detection-summary-dot detection-summary-dot--active" />
              42 ACTIVE
            </span>

            <span>
              <i className="detection-summary-dot detection-summary-dot--disabled" />
              05 DISABLED
            </span>
          </div>
        </div>

        <div className="detection-toolbar">
          <div className="detection-search">
            <Search size={16} />

            <input
              type="search"
              value={searchTerm}
              onChange={(event) =>
                setSearchTerm(event.target.value)
              }
              placeholder="Search rule ID, name, technique or source..."
              aria-label="Search detection rules"
            />
          </div>

          <div className="detection-filter">
            <Filter size={14} />

            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
              aria-label="Filter by severity"
            >
              {severityOptions.map((option) => (
                <option value={option} key={option}>
                  {option === "ALL"
                    ? "All severities"
                    : option}
                </option>
              ))}
            </select>

            <ChevronDown size={14} />
          </div>

          <div className="detection-filter">
            <ShieldAlert size={14} />

            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value)
              }
              aria-label="Filter by status"
            >
              {statusOptions.map((option) => (
                <option value={option} key={option}>
                  {option === "ALL"
                    ? "All statuses"
                    : option}
                </option>
              ))}
            </select>

            <ChevronDown size={14} />
          </div>
        </div>

        <div className="detection-table-head">
          <span>RULE</span>
          <span>MITRE</span>
          <span>SEVERITY</span>
          <span>STATUS</span>
          <span>TRIGGERS</span>
          <span>LAST ACTIVITY</span>
          <span />
        </div>

        <div className="detection-rules">
          {filteredRules.length > 0 ? (
            filteredRules.map((rule) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                onSelect={setSelectedRule}
              />
            ))
          ) : (
            <div className="detection-empty">
              <Search size={25} />

              <strong>No detection rules found</strong>

              <p>
                Try adjusting your search or filter
                criteria.
              </p>
            </div>
          )}
        </div>
      </section>

      <footer className="detections-footer">
        <div>
          <span className="detections-footer__pulse" />
          DETECTION ENGINE ONLINE
        </div>

        <span>
          MITRE ATT&amp;CK COVERAGE 91.4%
        </span>

        <span>
          RULE EVALUATION &lt; 120 MS
        </span>
      </footer>

      <RuleDetails
        rule={selectedRule}
        onClose={() => setSelectedRule(null)}
      />
    </div>
  );
}

export default Detections;