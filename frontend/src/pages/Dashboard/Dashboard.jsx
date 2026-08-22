import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  Clock3,
  Flame,
  Globe2,
  LockKeyhole,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Target,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./Dashboard.css";

const threatActivity = [
  { time: "00:00", critical: 2, high: 8, medium: 17 },
  { time: "02:00", critical: 1, high: 6, medium: 14 },
  { time: "04:00", critical: 3, high: 11, medium: 19 },
  { time: "06:00", critical: 2, high: 9, medium: 23 },
  { time: "08:00", critical: 5, high: 16, medium: 31 },
  { time: "10:00", critical: 4, high: 19, medium: 35 },
  { time: "12:00", critical: 7, high: 22, medium: 41 },
  { time: "14:00", critical: 5, high: 18, medium: 38 },
  { time: "16:00", critical: 3, high: 14, medium: 29 },
  { time: "18:00", critical: 4, high: 17, medium: 33 },
  { time: "20:00", critical: 2, high: 12, medium: 25 },
  { time: "22:00", critical: 1, high: 8, medium: 18 },
];

const activeThreats = [
  {
    id: "INC-2048",
    title: "Credential access attempt",
    source: "10.24.18.42",
    technique: "T1110",
    severity: "CRITICAL",
    age: "8m",
  },
  {
    id: "INC-2047",
    title: "Suspicious PowerShell execution",
    source: "10.24.9.117",
    technique: "T1059.001",
    severity: "HIGH",
    age: "14m",
  },
  {
    id: "INC-2046",
    title: "Unusual outbound connection",
    source: "10.24.6.31",
    technique: "T1071.001",
    severity: "HIGH",
    age: "21m",
  },
  {
    id: "INC-2045",
    title: "Privilege escalation detected",
    source: "10.24.3.88",
    technique: "T1548",
    severity: "MEDIUM",
    age: "37m",
  },
];

const recentEvents = [
  {
    time: "23:18:42",
    type: "AUTH",
    message: "Multiple failed authentication attempts",
    source: "10.24.18.42",
    severity: "HIGH",
  },
  {
    time: "23:16:08",
    type: "PROCESS",
    message: "Encoded PowerShell command detected",
    source: "10.24.9.117",
    severity: "CRITICAL",
  },
  {
    time: "23:14:31",
    type: "NETWORK",
    message: "Outbound connection matched IOC",
    source: "10.24.6.31",
    severity: "HIGH",
  },
  {
    time: "23:11:57",
    type: "FILE",
    message: "Sensitive configuration file accessed",
    source: "10.24.3.88",
    severity: "MEDIUM",
  },
  {
    time: "23:08:13",
    type: "SYSTEM",
    message: "Security agent heartbeat received",
    source: "10.24.2.15",
    severity: "LOW",
  },
];

const metrics = [
  {
    label: "Critical Threats",
    value: "07",
    change: "+2",
    trend: "up",
    icon: Siren,
    tone: "critical",
  },
  {
    label: "Active Incidents",
    value: "04",
    change: "-1",
    trend: "down",
    icon: ShieldAlert,
    tone: "warning",
  },
  {
    label: "Events / Hour",
    value: "18.4K",
    change: "+12.8%",
    trend: "up",
    icon: Activity,
    tone: "cyan",
  },
  {
    label: "Detection Rate",
    value: "98.7%",
    change: "+0.8%",
    trend: "up",
    icon: Target,
    tone: "success",
  },
];

function MetricCard({ metric }) {
  const Icon = metric.icon;
  const TrendIcon = metric.trend === "up" ? ArrowUpRight : ArrowDownRight;

  return (
    <article className={`dashboard-metric dashboard-metric--${metric.tone}`}>
      <div className="dashboard-metric__top">
        <div className="dashboard-metric__icon">
          <Icon size={18} strokeWidth={1.8} />
        </div>

        <span className="dashboard-metric__label">
          {metric.label}
        </span>
      </div>

      <div className="dashboard-metric__value">
        {metric.value}
      </div>

      <div className="dashboard-metric__footer">
        <span
          className={`dashboard-metric__change dashboard-metric__change--${metric.trend}`}
        >
          <TrendIcon size={13} />
          {metric.change}
        </span>

        <span className="dashboard-metric__period">
          vs previous hour
        </span>
      </div>
    </article>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span
      className={`severity-badge severity-badge--${severity.toLowerCase()}`}
    >
      <span className="severity-badge__dot" />
      {severity}
    </span>
  );
}

function ThreatActivityChart() {
  return (
    <section className="dashboard-panel dashboard-panel--chart">
      <div className="dashboard-panel__header">
        <div>
          <span className="dashboard-eyebrow">
            <Activity size={13} />
            LIVE TELEMETRY
          </span>

          <h2>Threat Activity</h2>

          <p>
            Detection volume across the last 24 hours.
          </p>
        </div>

        <div className="dashboard-chart-legend">
          <span>
            <i className="dashboard-chart-legend__dot dashboard-chart-legend__dot--critical" />
            Critical
          </span>

          <span>
            <i className="dashboard-chart-legend__dot dashboard-chart-legend__dot--high" />
            High
          </span>

          <span>
            <i className="dashboard-chart-legend__dot dashboard-chart-legend__dot--medium" />
            Medium
          </span>
        </div>
      </div>

      <div className="dashboard-chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={threatActivity}>
            <defs>
              <linearGradient id="criticalGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopOpacity={0.35} />
                <stop offset="100%" stopOpacity={0} />
              </linearGradient>

              <linearGradient id="highGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopOpacity={0.25} />
                <stop offset="100%" stopOpacity={0} />
              </linearGradient>

              <linearGradient id="mediumGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopOpacity={0.18} />
                <stop offset="100%" stopOpacity={0} />
              </linearGradient>
            </defs>

            <CartesianGrid
              stroke="rgba(132, 161, 188, 0.08)"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              axisLine={false}
              tickLine={false}
              tick={{
                fill: "#62758a",
                fontSize: 11,
              }}
            />

            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{
                fill: "#62758a",
                fontSize: 11,
              }}
              width={32}
            />

            <Tooltip
              contentStyle={{
                background: "#0b131c",
                border: "1px solid rgba(54, 214, 255, 0.22)",
                borderRadius: "10px",
                color: "#e7f0f7",
                boxShadow: "0 16px 40px rgba(0, 0, 0, 0.35)",
              }}
              labelStyle={{
                color: "#7e93a8",
                marginBottom: "6px",
              }}
            />

            <Area
              type="monotone"
              dataKey="medium"
              stroke="#63778b"
              strokeWidth={1.5}
              fill="url(#mediumGradient)"
              fillOpacity={1}
            />

            <Area
              type="monotone"
              dataKey="high"
              stroke="#f5a524"
              strokeWidth={1.8}
              fill="url(#highGradient)"
              fillOpacity={1}
            />

            <Area
              type="monotone"
              dataKey="critical"
              stroke="#ff4d67"
              strokeWidth={2}
              fill="url(#criticalGradient)"
              fillOpacity={1}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function ActiveThreats() {
  return (
    <section className="dashboard-panel">
      <div className="dashboard-panel__header">
        <div>
          <span className="dashboard-eyebrow">
            <Flame size={13} />
            RESPONSE QUEUE
          </span>

          <h2>Active Threats</h2>

          <p>Threats requiring analyst attention.</p>
        </div>

        <span className="dashboard-live-indicator">
          <span />
          LIVE
        </span>
      </div>

      <div className="dashboard-threat-list">
        {activeThreats.map((threat) => (
          <article className="dashboard-threat" key={threat.id}>
            <div className="dashboard-threat__severity">
              <SeverityBadge severity={threat.severity} />
            </div>

            <div className="dashboard-threat__content">
              <div className="dashboard-threat__title">
                {threat.title}
              </div>

              <div className="dashboard-threat__meta">
                <span>{threat.id}</span>
                <span>{threat.source}</span>
                <span>{threat.technique}</span>
              </div>
            </div>

            <div className="dashboard-threat__age">
              <Clock3 size={13} />
              {threat.age}
            </div>
          </article>
        ))}
      </div>

      <button className="dashboard-panel__action" type="button">
        View all active threats
        <ArrowUpRight size={15} />
      </button>
    </section>
  );
}

function RecentEvents() {
  return (
    <section className="dashboard-panel dashboard-panel--events">
      <div className="dashboard-panel__header">
        <div>
          <span className="dashboard-eyebrow">
            <Globe2 size={13} />
            SECURITY TELEMETRY
          </span>

          <h2>Recent Security Events</h2>

          <p>Latest events received by the defense node.</p>
        </div>

        <span className="dashboard-event-count">
          18,421 EVENTS
        </span>
      </div>

      <div className="dashboard-events">
        {recentEvents.map((event) => (
          <article className="dashboard-event" key={`${event.time}-${event.source}`}>
            <div className="dashboard-event__time">
              {event.time}
            </div>

            <div className="dashboard-event__indicator">
              <span />
            </div>

            <div className="dashboard-event__content">
              <div className="dashboard-event__top">
                <span className="dashboard-event__type">
                  {event.type}
                </span>

                <SeverityBadge severity={event.severity} />
              </div>

              <div className="dashboard-event__message">
                {event.message}
              </div>

              <div className="dashboard-event__source">
                SOURCE <strong>{event.source}</strong>
              </div>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function SystemHealth() {
  const systems = [
    {
      label: "Event Collector",
      value: "Operational",
      percentage: 99,
      icon: Activity,
    },
    {
      label: "Detection Engine",
      value: "Operational",
      percentage: 98,
      icon: Target,
    },
    {
      label: "Response Engine",
      value: "Operational",
      percentage: 96,
      icon: Bot,
    },
    {
      label: "Database",
      value: "Operational",
      percentage: 99,
      icon: LockKeyhole,
    },
  ];

  return (
    <section className="dashboard-panel dashboard-panel--health">
      <div className="dashboard-panel__header">
        <div>
          <span className="dashboard-eyebrow">
            <ShieldCheck size={13} />
            INFRASTRUCTURE
          </span>

          <h2>System Health</h2>

          <p>Defense node service status.</p>
        </div>
      </div>

      <div className="dashboard-health">
        {systems.map((system) => {
          const Icon = system.icon;

          return (
            <div className="dashboard-health__item" key={system.label}>
              <div className="dashboard-health__icon">
                <Icon size={16} />
              </div>

              <div className="dashboard-health__content">
                <div className="dashboard-health__top">
                  <span>{system.label}</span>

                  <strong>{system.percentage}%</strong>
                </div>

                <div className="dashboard-health__bar">
                  <span
                    style={{
                      width: `${system.percentage}%`,
                    }}
                  />
                </div>

                <small>
                  <CheckCircle2 size={11} />
                  {system.value}
                </small>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function Dashboard() {
  return (
    <div className="dashboard-page">
      <header className="dashboard-page__header">
        <div>
          <div className="dashboard-breadcrumb">
            CYBERDEFENSE-X
            <span>/</span>
            SOC
            <span>/</span>
            DASHBOARD
          </div>

          <div className="dashboard-title-row">
            <div>
              <h1>Security Operations Center</h1>

              <p>
                Real-time security posture, threat intelligence and
                response telemetry.
              </p>
            </div>

            <div className="dashboard-posture">
              <span className="dashboard-posture__icon">
                <ShieldCheck size={19} />
              </span>

              <div>
                <span>SECURITY POSTURE</span>
                <strong>DEFENDED</strong>
              </div>
            </div>
          </div>
        </div>
      </header>

      <section className="dashboard-metrics">
        {metrics.map((metric) => (
          <MetricCard key={metric.label} metric={metric} />
        ))}
      </section>

      <section className="dashboard-main-grid">
        <ThreatActivityChart />

        <ActiveThreats />
      </section>

      <section className="dashboard-bottom-grid">
        <RecentEvents />

        <SystemHealth />
      </section>

      <footer className="dashboard-footer">
        <div>
          <span className="dashboard-footer__pulse" />
          DEFENSE NODE ONLINE
        </div>

        <span>
          CYBERDEFENSE-X SECURITY OPERATIONS PLATFORM
        </span>

        <span>
          TELEMETRY REFRESH &lt; 5 SEC
        </span>
      </footer>
    </div>
  );
}

export default Dashboard;