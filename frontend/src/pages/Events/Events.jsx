import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Cpu,
  Database,
  FileWarning,
  Filter,
  Globe2,
  KeyRound,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Terminal,
  UserRound,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";

import EventSeverityBadge from "../../components/events/EventSeverityBadge";

import "./Events.css";

const EVENT_DATA = [
  {
    id: "EVT-84921",
    timestamp: "23:18:42",
    date: "2026-08-20",
    type: "AUTHENTICATION",
    category: "AUTH",
    title: "Multiple failed authentication attempts",
    description:
      "Repeated authentication failures detected against a privileged account within a short time window.",
    source: "10.24.18.42",
    destination: "auth-gateway-01",
    user: "administrator",
    severity: "HIGH",
    technique: "T1110",
    techniqueName: "Brute Force",
    rule: "AUTH-BRUTE-001",
    status: "DETECTED",
    icon: KeyRound,
  },
  {
    id: "EVT-84920",
    timestamp: "23:16:08",
    date: "2026-08-20",
    type: "PROCESS",
    category: "ENDPOINT",
    title: "Encoded PowerShell command detected",
    description:
      "A PowerShell process executed an encoded command containing suspicious execution parameters.",
    source: "10.24.9.117",
    destination: "WIN-SOC-042",
    user: "svc_backup",
    severity: "CRITICAL",
    technique: "T1059.001",
    techniqueName: "PowerShell",
    rule: "PROC-PS-004",
    status: "DETECTED",
    icon: Terminal,
  },
  {
    id: "EVT-84919",
    timestamp: "23:14:31",
    date: "2026-08-20",
    type: "NETWORK",
    category: "NETWORK",
    title: "Outbound connection matched IOC",
    description:
      "Outbound traffic matched a known malicious indicator in the threat intelligence database.",
    source: "10.24.6.31",
    destination: "185.220.101.44",
    user: "system",
    severity: "HIGH",
    technique: "T1071.001",
    techniqueName: "Web Protocols",
    rule: "NET-IOC-012",
    status: "BLOCKED",
    icon: Network,
  },
  {
    id: "EVT-84918",
    timestamp: "23:11:57",
    date: "2026-08-20",
    type: "FILE ACCESS",
    category: "FILE",
    title: "Sensitive configuration file accessed",
    description:
      "A protected configuration file was accessed by a process outside the expected administrative workflow.",
    source: "10.24.3.88",
    destination: "linux-app-07",
    user: "deploy",
    severity: "MEDIUM",
    technique: "T1005",
    techniqueName: "Data from Local System",
    rule: "FILE-SENSITIVE-003",
    status: "MONITORED",
    icon: FileWarning,
  },
  {
    id: "EVT-84917",
    timestamp: "23:08:13",
    date: "2026-08-20",
    type: "SYSTEM",
    category: "SYSTEM",
    title: "Security agent heartbeat received",
    description:
      "Endpoint security agent reported a healthy heartbeat to the defense node.",
    source: "10.24.2.15",
    destination: "collector-01",
    user: "system",
    severity: "LOW",
    technique: "T1562",
    techniqueName: "Impair Defenses",
    rule: "AGENT-HEALTH-001",
    status: "RESOLVED",
    icon: Cpu,
  },
  {
    id: "EVT-84916",
    timestamp: "23:04:46",
    date: "2026-08-20",
    type: "PRIVILEGE",
    category: "IDENTITY",
    title: "Unexpected privilege escalation",
    description:
      "A user account received elevated privileges outside the approved change window.",
    source: "10.24.11.64",
    destination: "AD-CORE-01",
    user: "j.miller",
    severity: "CRITICAL",
    technique: "T1548",
    techniqueName: "Abuse Elevation Control",
    rule: "IDENTITY-PRIV-007",
    status: "INVESTIGATING",
    icon: ShieldAlert,
  },
  {
    id: "EVT-84915",
    timestamp: "22:58:22",
    date: "2026-08-20",
    type: "DNS",
    category: "NETWORK",
    title: "Suspicious DNS query observed",
    description:
      "Endpoint generated a DNS query associated with an anomalous domain reputation.",
    source: "10.24.14.27",
    destination: "dns-resolver-02",
    user: "system",
    severity: "MEDIUM",
    technique: "T1071.004",
    techniqueName: "DNS",
    rule: "DNS-ANOMALY-002",
    status: "DETECTED",
    icon: Globe2,
  },
  {
    id: "EVT-84914",
    timestamp: "22:51:03",
    date: "2026-08-20",
    type: "DATABASE",
    category: "DATA",
    title: "Unusual database query volume",
    description:
      "A database account generated a query volume significantly above its normal baseline.",
    source: "10.24.20.12",
    destination: "db-prod-01",
    user: "reporting",
    severity: "HIGH",
    technique: "T1213",
    techniqueName: "Data from Information Repositories",
    rule: "DB-VOLUME-006",
    status: "DETECTED",
    icon: Database,
  },
];

const EVENT_FILTERS = [
  "ALL EVENTS",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

const EVENT_METRICS = [
  {
    label: "Events / Hour",
    value: "18.4K",
    change: "+12.8%",
    trend: "up",
    tone: "cyan",
    icon: Activity,
  },
  {
    label: "Critical Events",
    value: "07",
    change: "+2",
    trend: "up",
    tone: "critical",
    icon: ShieldAlert,
  },
  {
    label: "Blocked Events",
    value: "1,284",
    change: "+8.4%",
    trend: "up",
    tone: "warning",
    icon: Network,
  },
  {
    label: "Collection Health",
    value: "99.4%",
    change: "+0.3%",
    trend: "up",
    tone: "success",
    icon: Server,
  },
];

function MetricCard({ metric }) {
  const Icon = metric.icon;
  const TrendIcon =
    metric.trend === "up" ? ArrowUpRight : ArrowDownRight;

  return (
    <article className={`events-metric events-metric--${metric.tone}`}>
      <div className="events-metric__top">
        <span className="events-metric__icon">
          <Icon size={17} strokeWidth={1.8} />
        </span>

        <span className="events-metric__label">
          {metric.label}
        </span>
      </div>

      <strong className="events-metric__value">
        {metric.value}
      </strong>

      <div className="events-metric__footer">
        <span
          className={`events-metric__change events-metric__change--${metric.trend}`}
        >
          <TrendIcon size={13} />
          {metric.change}
        </span>

        <span>vs previous hour</span>
      </div>
    </article>
  );
}

function EventRow({ event, expanded, onToggle }) {
  const Icon = event.icon;

  return (
    <article
      className={`event-row ${
        expanded ? "event-row--expanded" : ""
      }`}
    >
      <button
        type="button"
        className="event-row__main"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <div className="event-row__time">
          <strong>{event.timestamp}</strong>
          <span>{event.id}</span>
        </div>

        <div className="event-row__severity-marker">
          <span />
        </div>

        <div className="event-row__icon">
          <Icon size={17} strokeWidth={1.8} />
        </div>

        <div className="event-row__content">
          <div className="event-row__title-line">
            <span className="event-row__type">
              {event.type}
            </span>

            <EventSeverityBadge severity={event.severity} />
          </div>

          <h3>{event.title}</h3>

          <div className="event-row__meta">
            <span>
              <Network size={11} />
              {event.source}
            </span>

            <span>
              <Server size={11} />
              {event.destination}
            </span>

            <span>
              <UserRound size={11} />
              {event.user}
            </span>
          </div>
        </div>

        <div className="event-row__technique">
          <span>{event.technique}</span>
          <small>{event.techniqueName}</small>
        </div>

        <div
          className={`event-row__status event-row__status--${event.status.toLowerCase()}`}
        >
          {event.status}
        </div>

        <span className="event-row__expand">
          <ChevronDown
            size={15}
            className={
              expanded ? "event-row__chevron--open" : ""
            }
          />
        </span>
      </button>

      {expanded && (
        <div className="event-row__details">
          <div className="event-detail-card event-detail-card--description">
            <span className="event-detail-card__label">
              EVENT DESCRIPTION
            </span>

            <p>{event.description}</p>
          </div>

          <div className="event-detail-card">
            <span className="event-detail-card__label">
              DETECTION RULE
            </span>

            <strong>{event.rule}</strong>
          </div>

          <div className="event-detail-card">
            <span className="event-detail-card__label">
              MITRE TECHNIQUE
            </span>

            <strong>{event.technique}</strong>
            <small>{event.techniqueName}</small>
          </div>

          <div className="event-detail-card">
            <span className="event-detail-card__label">
              OBSERVED
            </span>

            <strong>{event.date}</strong>
            <small>{event.timestamp} UTC</small>
          </div>
        </div>
      )}
    </article>
  );
}

function Events() {
  const [activeFilter, setActiveFilter] =
    useState("ALL EVENTS");

  const [searchQuery, setSearchQuery] = useState("");

  const [expandedEvent, setExpandedEvent] =
    useState(null);

  const filteredEvents = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    return EVENT_DATA.filter((event) => {
      const matchesSeverity =
        activeFilter === "ALL EVENTS" ||
        event.severity === activeFilter;

      if (!matchesSeverity) {
        return false;
      }

      if (!query) {
        return true;
      }

      return [
        event.id,
        event.type,
        event.category,
        event.title,
        event.description,
        event.source,
        event.destination,
        event.user,
        event.severity,
        event.technique,
        event.techniqueName,
        event.rule,
        event.status,
      ].some((value) =>
        String(value).toLowerCase().includes(query),
      );
    });
  }, [activeFilter, searchQuery]);

  const toggleEvent = (eventId) => {
    setExpandedEvent((current) =>
      current === eventId ? null : eventId,
    );
  };

  const clearFilters = () => {
    setSearchQuery("");
    setActiveFilter("ALL EVENTS");
    setExpandedEvent(null);
  };

  return (
    <div className="events-page">
      <header className="events-page__header">
        <div className="events-breadcrumb">
          <span>CYBERDEFENSE-X</span>
          <i>/</i>
          <span>SOC</span>
          <i>/</i>
          <strong>TELEMETRY</strong>
        </div>

        <div className="events-title-row">
          <div>
            <div className="events-eyebrow">
              <Activity size={13} />
              SECURITY TELEMETRY
            </div>

            <h1>Security Events</h1>

            <p>
              Investigate endpoint, identity, network and
              system telemetry across the defense node.
            </p>
          </div>

          <div className="events-live-status">
            <span className="events-live-status__pulse" />

            <div>
              <strong>LIVE STREAM</strong>
              <span>COLLECTORS OPERATIONAL</span>
            </div>

            <RefreshCw size={15} />
          </div>
        </div>
      </header>

      <section className="events-metrics">
        {EVENT_METRICS.map((metric) => (
          <MetricCard
            key={metric.label}
            metric={metric}
          />
        ))}
      </section>

      <section className="events-workspace">
        <div className="events-workspace__header">
          <div>
            <span className="events-section-kicker">
              <Terminal size={13} />
              EVENT STREAM
            </span>

            <h2>Latest Security Telemetry</h2>

            <p>
              Real-time events received from protected
              infrastructure.
            </p>
          </div>

          <div className="events-workspace__counter">
            <strong>
              {String(filteredEvents.length).padStart(2, "0")}
            </strong>
            <span>VISIBLE EVENTS</span>
          </div>
        </div>

        <div className="events-controls">
          <div className="events-search">
            <Search size={15} />

            <input
              type="search"
              value={searchQuery}
              onChange={(event) =>
                setSearchQuery(event.target.value)
              }
              placeholder="Search events, IPs, users, rules..."
              aria-label="Search security events"
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

          <div className="events-filter">
            <Filter size={14} />

            {EVENT_FILTERS.map((filter) => (
              <button
                type="button"
                key={filter}
                className={
                  activeFilter === filter
                    ? "events-filter__button events-filter__button--active"
                    : "events-filter__button"
                }
                onClick={() => {
                  setActiveFilter(filter);
                  setExpandedEvent(null);
                }}
              >
                {filter}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="events-stream-panel">
        <div className="events-stream-panel__header">
          <div className="events-stream-panel__identity">
            <span className="events-stream-panel__live-dot" />

            <div>
              <strong>DEFENSE NODE EVENT FEED</strong>
              <span>
                <Clock3 size={11} />
                LAST UPDATE 23:18:42 UTC
              </span>
            </div>
          </div>

          <div className="events-stream-panel__summary">
            <span>
              <CheckCircle2 size={13} />
              COLLECTION HEALTHY
            </span>

            <span>
              <Activity size={13} />
              18.4K / HR
            </span>
          </div>
        </div>

        <div className="events-stream">
          {filteredEvents.length > 0 ? (
            filteredEvents.map((event) => (
              <EventRow
                key={event.id}
                event={event}
                expanded={expandedEvent === event.id}
                onToggle={() => toggleEvent(event.id)}
              />
            ))
          ) : (
            <div className="events-empty">
              <div className="events-empty__icon">
                <Search size={24} />
              </div>

              <h3>No matching events</h3>

              <p>
                No telemetry matches the current search
                and severity filters.
              </p>

              <button
                type="button"
                onClick={clearFilters}
              >
                Clear filters
              </button>
            </div>
          )}
        </div>
      </section>

      <footer className="events-footer">
        <div>
          <span className="events-footer__pulse" />
          TELEMETRY PIPELINE ONLINE
        </div>

        <span>
          EVENT RETENTION <strong>30 DAYS</strong>
        </span>

        <span>
          INGESTION LATENCY <strong>&lt; 250 MS</strong>
        </span>

        <span>
          COLLECTORS <strong>04 / 04</strong>
        </span>
      </footer>
    </div>
  );
}

export default Events;