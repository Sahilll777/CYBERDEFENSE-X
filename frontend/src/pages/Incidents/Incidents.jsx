import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Eye,
  FileSearch,
  Flame,
  GitBranch,
  Globe2,
  History,
  Monitor,
  Search,
  ShieldAlert,
  ShieldCheck,
  Target,
  UserRound,
  Users,
  X,
  Zap,
} from "lucide-react";

import "./Incidents.css";

const incidents = [
  {
    id: "INC-2048",
    title: "Credential access attempt",
    description:
      "Repeated authentication failures followed by suspicious credential access activity against a privileged account.",
    severity: "CRITICAL",
    priority: "P1",
    status: "OPEN",
    source: "10.24.18.42",
    asset: "AUTH-SRV-04",
    technique: "T1110",
    techniqueName: "Brute Force",
    tactic: "Credential Access",
    analyst: "Security Analyst",
    created: "23:10:42",
    lastActivity: "8m ago",
    detections: 14,
    evidence: 7,
  },
  {
    id: "INC-2047",
    title: "Suspicious PowerShell execution",
    description:
      "Encoded PowerShell commands were detected on an internal endpoint after an unusual process chain.",
    severity: "HIGH",
    priority: "P2",
    status: "INVESTIGATING",
    source: "10.24.9.117",
    asset: "WKSTN-117",
    technique: "T1059.001",
    techniqueName: "PowerShell",
    tactic: "Execution",
    analyst: "Security Analyst",
    created: "23:04:08",
    lastActivity: "14m ago",
    detections: 9,
    evidence: 5,
  },
  {
    id: "INC-2046",
    title: "Unusual outbound connection",
    description:
      "Outbound network traffic matched a known malicious indicator associated with command-and-control activity.",
    severity: "HIGH",
    priority: "P2",
    status: "INVESTIGATING",
    source: "10.24.6.31",
    asset: "WEB-NODE-31",
    technique: "T1071.001",
    techniqueName: "Web Protocols",
    tactic: "Command and Control",
    analyst: "Detection Analyst",
    created: "22:57:31",
    lastActivity: "21m ago",
    detections: 6,
    evidence: 4,
  },
  {
    id: "INC-2045",
    title: "Privilege escalation detected",
    description:
      "A non-administrative account performed activity associated with privilege escalation.",
    severity: "MEDIUM",
    priority: "P3",
    status: "OPEN",
    source: "10.24.3.88",
    asset: "APP-SRV-08",
    technique: "T1548",
    techniqueName: "Abuse Elevation Control",
    tactic: "Privilege Escalation",
    analyst: "Security Analyst",
    created: "22:41:57",
    lastActivity: "37m ago",
    detections: 4,
    evidence: 3,
  },
  {
    id: "INC-2044",
    title: "Sensitive configuration access",
    description:
      "A sensitive configuration file was accessed by a process outside its normal execution pattern.",
    severity: "MEDIUM",
    priority: "P3",
    status: "CONTAINED",
    source: "10.24.5.64",
    asset: "DB-NODE-02",
    technique: "T1552.001",
    techniqueName: "Credentials In Files",
    tactic: "Credential Access",
    analyst: "Detection Analyst",
    created: "22:19:13",
    lastActivity: "52m ago",
    detections: 3,
    evidence: 6,
  },
  {
    id: "INC-2043",
    title: "Endpoint malware indicator",
    description:
      "Endpoint telemetry identified a suspicious executable matching a known malware indicator.",
    severity: "HIGH",
    priority: "P2",
    status: "RESOLVED",
    source: "10.24.2.91",
    asset: "WKSTN-091",
    technique: "T1204.002",
    techniqueName: "Malicious File",
    tactic: "Initial Access",
    analyst: "Security Analyst",
    created: "21:48:06",
    lastActivity: "1h ago",
    detections: 8,
    evidence: 9,
  },
];

const timeline = [
  {
    time: "23:18:42",
    title: "Detection triggered",
    description:
      "Multiple failed authentication events crossed the configured detection threshold.",
    type: "detection",
  },
  {
    time: "23:19:03",
    title: "Incident created",
    description:
      "Detection engine correlated activity and automatically created INC-2048.",
    type: "incident",
  },
  {
    time: "23:20:17",
    title: "Analyst assigned",
    description:
      "Incident assigned to Security Analyst for investigation.",
    type: "analyst",
  },
  {
    time: "23:22:51",
    title: "Evidence collected",
    description:
      "Seven related authentication and endpoint events were attached to the incident.",
    type: "evidence",
  },
];

const severityOrder = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function SeverityBadge({ severity }) {
  return (
    <span
      className={`incident-severity incident-severity--${severity.toLowerCase()}`}
    >
      <span />
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const labels = {
    OPEN: "Open",
    INVESTIGATING: "Investigating",
    CONTAINED: "Contained",
    RESOLVED: "Resolved",
  };

  return (
    <span
      className={`incident-status incident-status--${status.toLowerCase()}`}
    >
      {status === "RESOLVED" ? (
        <CheckCircle2 size={12} />
      ) : status === "CONTAINED" ? (
        <ShieldCheck size={12} />
      ) : (
        <span className="incident-status__dot" />
      )}

      {labels[status]}
    </span>
  );
}

function MetricCard({ icon: Icon, label, value, detail, tone }) {
  return (
    <article className={`incident-metric incident-metric--${tone}`}>
      <div className="incident-metric__top">
        <div className="incident-metric__icon">
          <Icon size={18} strokeWidth={1.8} />
        </div>

        <span>{label}</span>
      </div>

      <strong>{value}</strong>

      <div className="incident-metric__detail">
        {detail}
      </div>
    </article>
  );
}

function IncidentDetail({ incident, onClose }) {
  if (!incident) {
    return null;
  }

  return (
    <div className="incident-detail-backdrop" onClick={onClose}>
      <aside
        className="incident-detail"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="incident-detail__header">
          <div>
            <span className="incident-eyebrow">
              <ShieldAlert size={13} />
              INCIDENT INVESTIGATION
            </span>

            <h2>{incident.id}</h2>

            <p>{incident.title}</p>
          </div>

          <button
            type="button"
            className="incident-detail__close"
            onClick={onClose}
            aria-label="Close incident details"
          >
            <X size={18} />
          </button>
        </div>

        <div className="incident-detail__summary">
          <SeverityBadge severity={incident.severity} />

          <StatusBadge status={incident.status} />

          <span className="incident-detail__priority">
            <Zap size={12} />
            {incident.priority}
          </span>
        </div>

        <div className="incident-detail__body">
          <section className="incident-detail__section">
            <div className="incident-detail__section-title">
              <FileSearch size={15} />
              Incident Summary
            </div>

            <p className="incident-detail__description">
              {incident.description}
            </p>
          </section>

          <section className="incident-detail__grid">
            <div>
              <span>Source</span>
              <strong>{incident.source}</strong>
            </div>

            <div>
              <span>Affected Asset</span>
              <strong>{incident.asset}</strong>
            </div>

            <div>
              <span>MITRE Technique</span>
              <strong>{incident.technique}</strong>
            </div>

            <div>
              <span>Tactic</span>
              <strong>{incident.tactic}</strong>
            </div>

            <div>
              <span>Assigned Analyst</span>
              <strong>{incident.analyst}</strong>
            </div>

            <div>
              <span>Related Detections</span>
              <strong>{incident.detections}</strong>
            </div>
          </section>

          <section className="incident-detail__section">
            <div className="incident-detail__section-title">
              <History size={15} />
              Investigation Timeline
            </div>

            <div className="incident-timeline">
              {timeline.map((event) => (
                <div
                  className="incident-timeline__item"
                  key={`${event.time}-${event.title}`}
                >
                  <div className="incident-timeline__marker">
                    {event.type === "detection" ? (
                      <Target size={12} />
                    ) : event.type === "analyst" ? (
                      <UserRound size={12} />
                    ) : event.type === "evidence" ? (
                      <FileSearch size={12} />
                    ) : (
                      <ShieldAlert size={12} />
                    )}
                  </div>

                  <div>
                    <div className="incident-timeline__top">
                      <strong>{event.title}</strong>
                      <span>{event.time}</span>
                    </div>

                    <p>{event.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="incident-detail__actions">
            <button type="button">
              <Eye size={15} />
              Open Investigation
            </button>

            <button type="button">
              <Bot size={15} />
              Run Response Playbook
            </button>
          </section>
        </div>
      </aside>
    </div>
  );
}

function Incidents() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedIncident, setSelectedIncident] = useState(null);

  const filteredIncidents = useMemo(() => {
    const query = search.trim().toLowerCase();

    return incidents
      .filter((incident) => {
        const matchesSearch =
          !query ||
          [
            incident.id,
            incident.title,
            incident.source,
            incident.asset,
            incident.technique,
            incident.techniqueName,
            incident.analyst,
          ]
            .join(" ")
            .toLowerCase()
            .includes(query);

        const matchesSeverity =
          severityFilter === "ALL" ||
          incident.severity === severityFilter;

        const matchesStatus =
          statusFilter === "ALL" ||
          incident.status === statusFilter;

        return matchesSearch && matchesSeverity && matchesStatus;
      })
      .sort(
        (a, b) =>
          severityOrder[b.severity] -
          severityOrder[a.severity],
      );
  }, [search, severityFilter, statusFilter]);

  return (
    <div className="incidents-page">
      <header className="incidents-page__header">
        <div>
          <div className="incidents-breadcrumb">
            CYBERDEFENSE-X
            <span>/</span>
            SOC
            <span>/</span>
            INCIDENTS
          </div>

          <div className="incidents-title-row">
            <div>
              <span className="incident-eyebrow">
                <ShieldAlert size={13} />
                INCIDENT RESPONSE CENTER
              </span>

              <h1>Security Incidents</h1>

              <p>
                Investigate, contain and resolve correlated
                security incidents across the defense node.
              </p>
            </div>

            <div className="incidents-posture">
              <div className="incidents-posture__icon">
                <ShieldCheck size={19} />
              </div>

              <div>
                <span>RESPONSE ENGINE</span>
                <strong>
                  <i />
                  OPERATIONAL
                </strong>
              </div>
            </div>
          </div>
        </div>
      </header>

      <section className="incidents-metrics">
        <MetricCard
          icon={SirenIcon}
          label="Critical Incidents"
          value="01"
          detail="+1 requires immediate attention"
          tone="critical"
        />

        <MetricCard
          icon={Flame}
          label="Open Incidents"
          value="04"
          detail="2 added in the last hour"
          tone="warning"
        />

        <MetricCard
          icon={Users}
          label="Under Investigation"
          value="02"
          detail="Currently assigned to analysts"
          tone="cyan"
        />

        <MetricCard
          icon={Clock3}
          label="Mean Time to Respond"
          value="04m 21s"
          detail="-18.4% vs previous period"
          tone="success"
        />
      </section>

      <section className="incidents-panel">
        <div className="incidents-panel__header">
          <div>
            <span className="incident-eyebrow">
              <GitBranch size={13} />
              INCIDENT CORRELATION
            </span>

            <h2>Incident Queue</h2>

            <p>
              Correlated security activity requiring analyst
              investigation and response.
            </p>
          </div>

          <div className="incidents-panel__live">
            <span />
            LIVE INCIDENT STREAM
          </div>
        </div>

        <div className="incidents-toolbar">
          <label className="incidents-search">
            <Search size={16} />

            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search incident ID, asset, source, technique..."
            />
          </label>

          <label className="incidents-select">
            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            <ChevronDown size={14} />
          </label>

          <label className="incidents-select">
            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value)
              }
            >
              <option value="ALL">All statuses</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">
                Investigating
              </option>
              <option value="CONTAINED">Contained</option>
              <option value="RESOLVED">Resolved</option>
            </select>

            <ChevronDown size={14} />
          </label>
        </div>

        <div className="incident-table">
          <div className="incident-table__header">
            <span>INCIDENT</span>
            <span>SEVERITY</span>
            <span>STATUS</span>
            <span>MITRE ATT&CK</span>
            <span>ASSIGNED</span>
            <span>ACTIVITY</span>
            <span />
          </div>

          <div className="incident-table__body">
            {filteredIncidents.map((incident) => (
              <button
                type="button"
                className="incident-row"
                key={incident.id}
                onClick={() => setSelectedIncident(incident)}
              >
                <div className="incident-row__identity">
                  <div className="incident-row__icon">
                    <ShieldAlert size={17} />
                  </div>

                  <div>
                    <strong>
                      {incident.title}
                    </strong>

                    <span>
                      {incident.id}
                      <i>•</i>
                      {incident.source}
                      <i>•</i>
                      {incident.asset}
                    </span>
                  </div>
                </div>

                <div>
                  <SeverityBadge
                    severity={incident.severity}
                  />
                </div>

                <div>
                  <StatusBadge status={incident.status} />
                </div>

                <div className="incident-row__mitre">
                  <strong>{incident.technique}</strong>
                  <span>{incident.techniqueName}</span>
                </div>

                <div className="incident-row__analyst">
                  <UserRound size={13} />
                  {incident.analyst}
                </div>

                <div className="incident-row__activity">
                  <Clock3 size={13} />
                  <span>{incident.lastActivity}</span>
                </div>

                <div className="incident-row__open">
                  <ArrowRight size={16} />
                </div>
              </button>
            ))}

            {filteredIncidents.length === 0 && (
              <div className="incident-empty">
                <Search size={22} />

                <strong>No incidents found</strong>

                <span>
                  Try adjusting your search or filters.
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="incidents-panel__footer">
          <span>
            SHOWING{" "}
            <strong>{filteredIncidents.length}</strong>{" "}
            OF <strong>{incidents.length}</strong> INCIDENTS
          </span>

          <span>
            <Globe2 size={13} />
            LOCAL DEFENSE NODE
          </span>
        </div>
      </section>

      <section className="incident-intelligence">
        <article className="incident-intelligence__card">
          <div className="incident-intelligence__icon">
            <Target size={17} />
          </div>

          <div>
            <span>TOP ATTACK TACTIC</span>
            <strong>Credential Access</strong>
            <small>38% of active incidents</small>
          </div>
        </article>

        <article className="incident-intelligence__card">
          <div className="incident-intelligence__icon">
            <Monitor size={17} />
          </div>

          <div>
            <span>MOST AFFECTED ASSET</span>
            <strong>AUTH-SRV-04</strong>
            <small>6 correlated detections</small>
          </div>
        </article>

        <article className="incident-intelligence__card">
          <div className="incident-intelligence__icon">
            <Zap size={17} />
          </div>

          <div>
            <span>RESPONSE AUTOMATION</span>
            <strong>72% automated</strong>
            <small>Containment playbooks available</small>
          </div>
        </article>

        <article className="incident-intelligence__card">
          <div className="incident-intelligence__icon">
            <CheckCircle2 size={17} />
          </div>

          <div>
            <span>RESOLUTION RATE</span>
            <strong>96.4%</strong>
            <small>Incidents resolved within SLA</small>
          </div>
        </article>
      </section>

      <footer className="incidents-footer">
        <span>
          <i />
          INCIDENT RESPONSE ENGINE ONLINE
        </span>

        <span>
          CYBERDEFENSE-X SECURITY OPERATIONS PLATFORM
        </span>

        <span>
          CORRELATION REFRESH &lt; 5 SEC
        </span>
      </footer>

      <IncidentDetail
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />
    </div>
  );
}

function SirenIcon(props) {
  return <AlertTriangle {...props} />;
}

export default Incidents;