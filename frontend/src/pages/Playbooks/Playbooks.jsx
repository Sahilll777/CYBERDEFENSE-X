import {
  Activity,
  AlertOctagon,
  ArrowDownRight,
  ArrowUpRight,
  Ban,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Filter,
  GitBranch,
  History,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UserRound,
  Workflow,
  X,
  Zap,
} from "lucide-react";
import { useMemo, useState } from "react";

import PlaybookStatusBadge from "../../components/playbooks/PlaybookStatusBadge";

import "./Playbooks.css";

const PLAYBOOKS = [
  {
    id: "PB-001",
    name: "Brute Force Response",
    description:
      "Automatically contains hosts generating repeated authentication failures and creates an investigation record.",
    category: "IDENTITY",
    trigger: "AUTH-BRUTE-001",
    severity: "HIGH",
    status: "ACTIVE",
    version: "v2.4",
    owner: "SOC AUTOMATION",
    lastModified: "18 Aug 2026",
    lastRun: "4 min ago",
    avgExecution: "18 sec",
    executions24h: 184,
    successful24h: 178,
    failed24h: 6,
    actions: [
      "Block source IP",
      "Disable account",
      "Create incident",
    ],
    icon: ShieldAlert,
    descriptionLong:
      "Detects repeated authentication failures from a single source and executes the configured containment sequence.",
  },
  {
    id: "PB-002",
    name: "Malicious IOC Containment",
    description:
      "Blocks confirmed malicious network indicators and isolates the affected endpoint for analyst review.",
    category: "NETWORK",
    trigger: "NET-IOC-012",
    severity: "CRITICAL",
    status: "ACTIVE",
    version: "v3.1",
    owner: "THREAT RESPONSE",
    lastModified: "19 Aug 2026",
    lastRun: "11 min ago",
    avgExecution: "24 sec",
    executions24h: 96,
    successful24h: 94,
    failed24h: 2,
    actions: [
      "Block IOC",
      "Isolate endpoint",
      "Create incident",
    ],
    icon: Ban,
    descriptionLong:
      "Responds to confirmed malicious indicators by blocking the indicator, isolating the endpoint, and opening an incident.",
  },
  {
    id: "PB-003",
    name: "Suspicious PowerShell Isolation",
    description:
      "Responds to high-confidence PowerShell detections by isolating the endpoint and collecting forensic context.",
    category: "ENDPOINT",
    trigger: "PROC-PS-004",
    severity: "CRITICAL",
    status: "ACTIVE",
    version: "v1.8",
    owner: "ENDPOINT SECURITY",
    lastModified: "17 Aug 2026",
    lastRun: "18 min ago",
    avgExecution: "31 sec",
    executions24h: 72,
    successful24h: 69,
    failed24h: 3,
    actions: [
      "Isolate endpoint",
      "Collect process tree",
      "Create incident",
    ],
    icon: Terminal,
    descriptionLong:
      "Contains suspicious PowerShell activity by isolating the endpoint and collecting process execution evidence.",
  },
  {
    id: "PB-004",
    name: "Privilege Escalation Response",
    description:
      "Restricts suspicious privilege escalation activity and alerts the security operations team.",
    category: "IDENTITY",
    trigger: "IDENTITY-PRIV-007",
    severity: "HIGH",
    status: "PAUSED",
    version: "v2.1",
    owner: "IDENTITY SECURITY",
    lastModified: "15 Aug 2026",
    lastRun: "2 hr ago",
    avgExecution: "15 sec",
    executions24h: 43,
    successful24h: 41,
    failed24h: 2,
    actions: [
      "Revoke privilege",
      "Lock account",
      "Notify analyst",
    ],
    icon: ShieldCheck,
    descriptionLong:
      "Responds to suspicious privilege changes by revoking elevated access and locking the associated account.",
  },
  {
    id: "PB-005",
    name: "Endpoint Malware Containment",
    description:
      "Isolates endpoints after confirmed malware detections and initiates evidence collection.",
    category: "ENDPOINT",
    trigger: "MALWARE-001",
    severity: "CRITICAL",
    status: "ACTIVE",
    version: "v2.7",
    owner: "ENDPOINT SECURITY",
    lastModified: "19 Aug 2026",
    lastRun: "3 hr ago",
    avgExecution: "42 sec",
    executions24h: 38,
    successful24h: 37,
    failed24h: 1,
    actions: [
      "Isolate endpoint",
      "Quarantine file",
      "Collect evidence",
    ],
    icon: AlertOctagon,
    descriptionLong:
      "Performs endpoint containment and evidence collection after a high-confidence malware detection.",
  },
  {
    id: "PB-006",
    name: "Configuration Drift Response",
    description:
      "Detects unauthorized security configuration changes and starts the remediation workflow.",
    category: "SYSTEM",
    trigger: "CONFIG-DRIFT-003",
    severity: "MEDIUM",
    status: "PAUSED",
    version: "v1.5",
    owner: "PLATFORM SECURITY",
    lastModified: "12 Aug 2026",
    lastRun: "6 hr ago",
    avgExecution: "36 sec",
    executions24h: 27,
    successful24h: 26,
    failed24h: 1,
    actions: [
      "Capture configuration",
      "Create ticket",
      "Notify owner",
    ],
    icon: GitBranch,
    descriptionLong:
      "Captures configuration changes, creates a remediation record, and notifies the responsible system owner.",
  },
];

const EXECUTION_HISTORY = [
  {
    id: "RUN-98214",
    playbook: "Brute Force Response",
    trigger: "AUTH-BRUTE-001",
    source: "10.24.18.42",
    started: "23:18:44",
    duration: "17 sec",
    status: "SUCCESS",
    actor: "AUTOMATION",
  },
  {
    id: "RUN-98213",
    playbook: "Malicious IOC Containment",
    trigger: "NET-IOC-012",
    source: "10.24.6.31",
    started: "23:14:34",
    duration: "22 sec",
    status: "SUCCESS",
    actor: "AUTOMATION",
  },
  {
    id: "RUN-98212",
    playbook: "Suspicious PowerShell Isolation",
    trigger: "PROC-PS-004",
    source: "10.24.9.117",
    started: "23:16:12",
    duration: "29 sec",
    status: "SUCCESS",
    actor: "ANALYST",
  },
  {
    id: "RUN-98211",
    playbook: "Brute Force Response",
    trigger: "AUTH-BRUTE-001",
    source: "10.24.12.71",
    started: "22:57:18",
    duration: "19 sec",
    status: "SUCCESS",
    actor: "AUTOMATION",
  },
  {
    id: "RUN-98210",
    playbook: "Privilege Escalation Response",
    trigger: "IDENTITY-PRIV-007",
    source: "10.24.11.64",
    started: "22:51:04",
    duration: "—",
    status: "FAILED",
    actor: "AUTOMATION",
  },
  {
    id: "RUN-98209",
    playbook: "Endpoint Malware Containment",
    trigger: "MALWARE-001",
    source: "10.24.4.92",
    started: "21:42:18",
    duration: "39 sec",
    status: "SUCCESS",
    actor: "AUTOMATION",
  },
];

const CATEGORIES = [
  "ALL",
  "IDENTITY",
  "NETWORK",
  "ENDPOINT",
  "SYSTEM",
];

function MetricCard({ icon: Icon, label, value, change, trend, tone }) {
  const TrendIcon =
    trend === "up" ? ArrowUpRight : ArrowDownRight;

  return (
    <article className={`playbook-metric playbook-metric--${tone}`}>
      <div className="playbook-metric__top">
        <span className="playbook-metric__icon">
          <Icon size={17} strokeWidth={1.9} />
        </span>

        <span className="playbook-metric__label">
          {label}
        </span>
      </div>

      <strong className="playbook-metric__value">
        {value}
      </strong>

      <div className="playbook-metric__footer">
        <span
          className={`playbook-metric__change playbook-metric__change--${trend}`}
        >
          <TrendIcon size={13} />
          {change}
        </span>

        <span>vs previous period</span>
      </div>
    </article>
  );
}

function RiskBadge({ severity }) {
  return (
    <span
      className={`playbook-risk playbook-risk--${severity.toLowerCase()}`}
    >
      {severity}
    </span>
  );
}

function PlaybookCard({
  playbook,
  onRun,
  onToggle,
  onInspect,
}) {
  const Icon = playbook.icon;

  const successRate =
    playbook.executions24h > 0
      ? Math.round(
          (playbook.successful24h /
            playbook.executions24h) *
            100,
        )
      : 0;

  return (
    <article className="playbook-card">
      <div className="playbook-card__top">
        <div className="playbook-card__identity">
          <div className="playbook-card__icon">
            <Icon size={19} strokeWidth={1.8} />
          </div>

          <div>
            <div className="playbook-card__id">
              {playbook.id}
            </div>

            <h3>{playbook.name}</h3>
          </div>
        </div>

        <PlaybookStatusBadge status={playbook.status} />
      </div>

      <p className="playbook-card__description">
        {playbook.description}
      </p>

      <div className="playbook-card__meta">
        <div>
          <span>TRIGGER</span>
          <strong>{playbook.trigger}</strong>
        </div>

        <div>
          <span>CATEGORY</span>
          <strong>{playbook.category}</strong>
        </div>

        <div>
          <span>VERSION</span>
          <strong>{playbook.version}</strong>
        </div>
      </div>

      <div className="playbook-card__chain">
        <div className="playbook-card__chain-header">
          <span>
            <Workflow size={12} />
            RESPONSE CHAIN
          </span>

          <span>{playbook.actions.length} ACTIONS</span>
        </div>

        <div className="playbook-card__chain-items">
          {playbook.actions.map((action, index) => (
            <div
              className="playbook-card__chain-item"
              key={action}
            >
              <span className="playbook-card__chain-number">
                {String(index + 1).padStart(2, "0")}
              </span>

              <span>{action}</span>

              {index <
                playbook.actions.length - 1 && (
                <ChevronRight size={12} />
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="playbook-card__stats">
        <div>
          <span>EXECUTIONS</span>
          <strong>{playbook.executions24h}</strong>
        </div>

        <div>
          <span>SUCCESS RATE</span>
          <strong>{successRate}%</strong>
        </div>

        <div>
          <span>AVG TIME</span>
          <strong>{playbook.avgExecution}</strong>
        </div>

        <div>
          <span>LAST RUN</span>
          <strong>{playbook.lastRun}</strong>
        </div>
      </div>

      <div className="playbook-card__success-track">
        <span style={{ width: `${successRate}%` }} />
      </div>

      <div className="playbook-card__footer">
        <div className="playbook-card__risk-block">
          <span>RISK LEVEL</span>
          <RiskBadge severity={playbook.severity} />
        </div>

        <div className="playbook-card__controls">
          <button
            type="button"
            className="playbook-card__inspect"
            onClick={() => onInspect(playbook)}
          >
            Inspect
          </button>

          <button
            type="button"
            className="playbook-card__toggle"
            onClick={() => onToggle(playbook.id)}
          >
            {playbook.status === "ACTIVE" ? (
              <>
                <Ban size={13} />
                Pause
              </>
            ) : (
              <>
                <Play size={13} />
                Enable
              </>
            )}
          </button>

          <button
            type="button"
            className="playbook-card__run"
            disabled={playbook.status !== "ACTIVE"}
            onClick={() => onRun(playbook)}
          >
            <Play size={12} fill="currentColor" />
            Run
          </button>
        </div>
      </div>
    </article>
  );
}

function ExecutionStatus({ status }) {
  const success = status === "SUCCESS";

  return (
    <span
      className={`execution-status execution-status--${
        success ? "success" : "failed"
      }`}
    >
      {success ? (
        <CheckCircle2 size={13} />
      ) : (
        <AlertOctagon size={13} />
      )}

      {status}
    </span>
  );
}

function ExecutionHistory() {
  const [historyFilter, setHistoryFilter] =
    useState("ALL");

  const filteredHistory = useMemo(() => {
    if (historyFilter === "ALL") {
      return EXECUTION_HISTORY;
    }

    return EXECUTION_HISTORY.filter(
      (execution) =>
        execution.status === historyFilter,
    );
  }, [historyFilter]);

  return (
    <section className="playbook-history">
      <div className="playbook-history__header">
        <div>
          <span className="playbooks-section-kicker">
            <History size={13} />
            EXECUTION TELEMETRY
          </span>

          <h2>Recent Executions</h2>

          <p>
            Latest automated response activity across the
            defense node.
          </p>
        </div>

        <div className="playbook-history__controls">
          <div className="playbook-history__filter">
            <Filter size={13} />

            <select
              value={historyFilter}
              onChange={(event) =>
                setHistoryFilter(event.target.value)
              }
              aria-label="Execution status filter"
            >
              <option value="ALL">All Runs</option>
              <option value="SUCCESS">
                Successful
              </option>
              <option value="FAILED">Failed</option>
            </select>

            <ChevronDown size={13} />
          </div>

          <button
            type="button"
            className="playbook-history__refresh"
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
      </div>

      <div className="playbook-history__table">
        <div className="playbook-history__row playbook-history__row--head">
          <span>RUN ID</span>
          <span>PLAYBOOK</span>
          <span>TRIGGER</span>
          <span>SOURCE</span>
          <span>STARTED</span>
          <span>DURATION</span>
          <span>ACTOR</span>
          <span>STATUS</span>
        </div>

        {filteredHistory.map((execution) => (
          <div
            className="playbook-history__row"
            key={execution.id}
          >
            <span className="playbook-run-id">
              {execution.id}
            </span>

            <span className="playbook-history__name">
              {execution.playbook}
            </span>

            <span className="playbook-history__trigger">
              {execution.trigger}
            </span>

            <span className="playbook-history__source">
              {execution.source}
            </span>

            <span className="playbook-history__time">
              {execution.started}
            </span>

            <span className="playbook-history__duration">
              {execution.duration}
            </span>

            <span className="playbook-history__actor">
              {execution.actor === "AUTOMATION" ? (
                <Bot size={12} />
              ) : (
                <UserRound size={12} />
              )}

              {execution.actor}
            </span>

            <ExecutionStatus status={execution.status} />
          </div>
        ))}

        {filteredHistory.length === 0 && (
          <div className="playbook-history__empty">
            <History size={24} />

            <span>No execution records found.</span>
          </div>
        )}
      </div>
    </section>
  );
}

function RunPlaybookModal({
  playbook,
  onClose,
  onConfirm,
}) {
  if (!playbook) {
    return null;
  }

  const PlaybookIcon = playbook.icon;

  return (
    <div
      className="playbook-modal__overlay"
      role="presentation"
      onMouseDown={onClose}
    >
      <div
        className="playbook-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="run-playbook-title"
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <div className="playbook-modal__header">
          <div>
            <span>MANUAL RESPONSE</span>

            <h2 id="run-playbook-title">
              Execute Playbook
            </h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        <div className="playbook-modal__body">
          <div className="playbook-modal__target">
            <div className="playbook-modal__target-icon">
              <PlaybookIcon size={20} />
            </div>

            <div>
              <span>{playbook.id}</span>
              <strong>{playbook.name}</strong>
            </div>
          </div>

          <div className="playbook-modal__warning">
            <AlertOctagon size={17} />

            <div>
              <strong>
                Manual execution requires authorization
              </strong>

              <p>
                This action will execute the configured
                response chain against the selected security
                context.
              </p>
            </div>
          </div>

          <div className="playbook-modal__grid">
            <div>
              <span>TRIGGER RULE</span>
              <strong>{playbook.trigger}</strong>
            </div>

            <div>
              <span>RISK LEVEL</span>
              <strong>{playbook.severity}</strong>
            </div>

            <div>
              <span>EXPECTED TIME</span>
              <strong>{playbook.avgExecution}</strong>
            </div>

            <div>
              <span>EXECUTION MODE</span>
              <strong>MANUAL</strong>
            </div>
          </div>

          <div className="playbook-modal__chain">
            <span>RESPONSE CHAIN</span>

            {playbook.actions.map((action, index) => (
              <div key={action}>
                <i>{String(index + 1).padStart(2, "0")}</i>
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="playbook-modal__footer">
          <button
            type="button"
            className="playbook-modal__cancel"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            type="button"
            className="playbook-modal__confirm"
            onClick={() => onConfirm(playbook)}
          >
            <Play size={14} fill="currentColor" />
            Confirm Execution
          </button>
        </div>
      </div>
    </div>
  );
}

function PlaybookDetailsDrawer({
  playbook,
  onClose,
  onRun,
}) {
  if (!playbook) {
    return null;
  }

  const Icon = playbook.icon;

  const successRate = Math.round(
    (playbook.successful24h /
      playbook.executions24h) *
      100,
  );

  return (
    <div
      className="playbook-drawer__overlay"
      role="presentation"
      onMouseDown={onClose}
    >
      <aside
        className="playbook-drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`${playbook.name} details`}
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        <header className="playbook-drawer__header">
          <div>
            <span>PLAYBOOK INSPECTOR</span>

            <h2>{playbook.name}</h2>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close playbook inspector"
          >
            <X size={18} />
          </button>
        </header>

        <div className="playbook-drawer__body">
          <div className="playbook-drawer__identity">
            <div className="playbook-drawer__icon">
              <Icon size={22} />
            </div>

            <div>
              <span>{playbook.id}</span>
              <strong>{playbook.version}</strong>
            </div>

            <PlaybookStatusBadge
              status={playbook.status}
            />
          </div>

          <p className="playbook-drawer__description">
            {playbook.descriptionLong}
          </p>

          <div className="playbook-drawer__section">
            <span className="playbook-drawer__section-title">
              CONFIGURATION
            </span>

            <div className="playbook-drawer__info-grid">
              <div>
                <span>TRIGGER</span>
                <strong>{playbook.trigger}</strong>
              </div>

              <div>
                <span>CATEGORY</span>
                <strong>{playbook.category}</strong>
              </div>

              <div>
                <span>OWNER</span>
                <strong>{playbook.owner}</strong>
              </div>

              <div>
                <span>LAST MODIFIED</span>
                <strong>{playbook.lastModified}</strong>
              </div>
            </div>
          </div>

          <div className="playbook-drawer__section">
            <span className="playbook-drawer__section-title">
              RESPONSE CHAIN
            </span>

            <div className="playbook-drawer__chain">
              {playbook.actions.map(
                (action, index) => (
                  <div key={action}>
                    <span>
                      {String(index + 1).padStart(
                        2,
                        "0",
                      )}
                    </span>

                    <div>
                      <strong>{action}</strong>

                      <small>
                        Action {index + 1} of{" "}
                        {playbook.actions.length}
                      </small>
                    </div>
                  </div>
                ),
              )}
            </div>
          </div>

          <div className="playbook-drawer__section">
            <span className="playbook-drawer__section-title">
              PERFORMANCE
            </span>

            <div className="playbook-drawer__performance">
              <div>
                <span>24H EXECUTIONS</span>
                <strong>{playbook.executions24h}</strong>
              </div>

              <div>
                <span>SUCCESS RATE</span>
                <strong>{successRate}%</strong>
              </div>

              <div>
                <span>AVG TIME</span>
                <strong>{playbook.avgExecution}</strong>
              </div>
            </div>

            <div className="playbook-drawer__progress">
              <span style={{ width: `${successRate}%` }} />
            </div>
          </div>
        </div>

        <footer className="playbook-drawer__footer">
          <button
            type="button"
            onClick={onClose}
          >
            Close
          </button>

          <button
            type="button"
            disabled={playbook.status !== "ACTIVE"}
            onClick={() => onRun(playbook)}
          >
            <Play size={13} fill="currentColor" />
            Run Playbook
          </button>
        </footer>
      </aside>
    </div>
  );
}

function Playbooks() {
  const [activeCategory, setActiveCategory] =
    useState("ALL");

  const [searchQuery, setSearchQuery] =
    useState("");

  const [selectedPlaybook, setSelectedPlaybook] =
    useState(null);

  const [executionPlaybook, setExecutionPlaybook] =
    useState(null);

  const [runningPlaybook, setRunningPlaybook] =
    useState(null);

  const [playbookStates, setPlaybookStates] =
    useState(
      Object.fromEntries(
        PLAYBOOKS.map((playbook) => [
          playbook.id,
          playbook.status,
        ]),
      ),
    );

  const filteredPlaybooks = useMemo(() => {
    const query = searchQuery
      .trim()
      .toLowerCase();

    return PLAYBOOKS.filter((playbook) => {
      const matchesCategory =
        activeCategory === "ALL" ||
        playbook.category === activeCategory;

      const searchableContent = [
        playbook.id,
        playbook.name,
        playbook.description,
        playbook.category,
        playbook.trigger,
        playbook.owner,
        ...playbook.actions,
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        !query ||
        searchableContent.includes(query);

      return matchesCategory && matchesSearch;
    });
  }, [activeCategory, searchQuery]);

  const metrics = useMemo(() => {
    const activeCount = PLAYBOOKS.filter(
      (playbook) =>
        playbookStates[playbook.id] === "ACTIVE",
    ).length;

    const executions = PLAYBOOKS.reduce(
      (sum, playbook) =>
        sum + playbook.executions24h,
      0,
    );

    const successful = PLAYBOOKS.reduce(
      (sum, playbook) =>
        sum + playbook.successful24h,
      0,
    );

    const failed = PLAYBOOKS.reduce(
      (sum, playbook) =>
        sum + playbook.failed24h,
      0,
    );

    return [
      {
        label: "Active Playbooks",
        value: String(activeCount).padStart(2, "0"),
        change: "+1",
        trend: "up",
        tone: "cyan",
        icon: Workflow,
      },
      {
        label: "Executions / 24H",
        value: executions.toLocaleString(),
        change: "+18.4%",
        trend: "up",
        tone: "success",
        icon: Zap,
      },
      {
        label: "Successful Runs",
        value: successful.toLocaleString(),
        change: "+2.1%",
        trend: "up",
        tone: "success",
        icon: CheckCircle2,
      },
      {
        label: "Failed Runs",
        value: failed.toLocaleString(),
        change: "-4.8%",
        trend: "down",
        tone: "warning",
        icon: AlertOctagon,
      },
    ];
  }, [playbookStates]);

  const togglePlaybook = (playbookId) => {
    setPlaybookStates((current) => ({
      ...current,
      [playbookId]:
        current[playbookId] === "ACTIVE"
          ? "PAUSED"
          : "ACTIVE",
    }));
  };

  const openExecution = (playbook) => {
    setSelectedPlaybook(null);

    setExecutionPlaybook({
      ...playbook,
      status: playbookStates[playbook.id],
    });
  };

  const confirmExecution = (playbook) => {
    setRunningPlaybook(playbook.id);
    setExecutionPlaybook(null);

    window.setTimeout(() => {
      setRunningPlaybook(null);
    }, 1400);
  };

  return (
    <div className="playbooks-page">
      <header className="playbooks-page__header">
        <div className="playbooks-breadcrumb">
          CYBERDEFENSE-X
          <span>/</span>
          SOC
          <span>/</span>
          RESPONSE
          <span>/</span>
          PLAYBOOKS
        </div>

        <div className="playbooks-title-row">
          <div>
            <div className="playbooks-eyebrow">
              <Workflow size={13} />
              SECURITY ORCHESTRATION
            </div>

            <h1>Response Playbooks</h1>

            <p>
              Orchestrate automated containment,
              remediation and response actions across the
              defense node.
            </p>
          </div>

          <div className="playbooks-engine-status">
            <span className="playbooks-engine-status__pulse" />

            <div>
              <strong>
                RESPONSE ENGINE ONLINE
              </strong>

              <span>
                SOAR AUTOMATION READY
              </span>
            </div>

            <Activity size={16} />
          </div>
        </div>
      </header>

      <section className="playbooks-metrics">
        {metrics.map((metric) => (
          <MetricCard
            key={metric.label}
            {...metric}
          />
        ))}
      </section>

      <section className="playbooks-library">
        <div className="playbooks-library__header">
          <div>
            <span className="playbooks-section-kicker">
              <Workflow size={13} />
              PLAYBOOK LIBRARY
            </span>

            <h2>Automated Response Workflows</h2>

            <p>
              Configured response chains available to the
              security operations team.
            </p>
          </div>

          <div className="playbooks-library__summary">
            <span>
              {filteredPlaybooks.length
                .toString()
                .padStart(2, "0")}
            </span>

            <small>VISIBLE PLAYBOOKS</small>
          </div>
        </div>

        <div className="playbooks-controls">
          <div className="playbooks-search">
            <Search size={15} />

            <input
              type="search"
              value={searchQuery}
              onChange={(event) =>
                setSearchQuery(event.target.value)
              }
              placeholder="Search playbooks, triggers, owners..."
              aria-label="Search playbooks"
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

          <div className="playbooks-filters">
            <Filter size={14} />

            {CATEGORIES.map((category) => (
              <button
                type="button"
                key={category}
                className={
                  activeCategory === category
                    ? "playbooks-filter playbooks-filter--active"
                    : "playbooks-filter"
                }
                onClick={() =>
                  setActiveCategory(category)
                }
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        <div className="playbooks-grid">
          {filteredPlaybooks.length > 0 ? (
            filteredPlaybooks.map((playbook) => (
              <PlaybookCard
                key={playbook.id}
                playbook={{
                  ...playbook,
                  status:
                    playbookStates[playbook.id],
                }}
                onRun={openExecution}
                onToggle={togglePlaybook}
                onInspect={setSelectedPlaybook}
              />
            ))
          ) : (
            <div className="playbooks-empty">
              <Search size={27} />

              <h3>No playbooks found</h3>

              <p>
                No response workflows match the current
                search or category filter.
              </p>

              <button
                type="button"
                onClick={() => {
                  setSearchQuery("");
                  setActiveCategory("ALL");
                }}
              >
                Clear Filters
              </button>
            </div>
          )}
        </div>
      </section>

      <ExecutionHistory />

      <footer className="playbooks-footer">
        <div>
          <span className="playbooks-footer__pulse" />
          RESPONSE ENGINE ONLINE
        </div>

        <span>
          AUTOMATION MODE{" "}
          <strong>LOCAL / SECURE</strong>
        </span>

        <span>
          EXECUTION QUEUE{" "}
          <strong>04 READY</strong>
        </span>

        <span>
          TELEMETRY{" "}
          <strong>LIVE</strong>
        </span>
      </footer>

      <RunPlaybookModal
        playbook={executionPlaybook}
        onClose={() => setExecutionPlaybook(null)}
        onConfirm={confirmExecution}
      />

      <PlaybookDetailsDrawer
        playbook={
          selectedPlaybook
            ? {
                ...selectedPlaybook,
                status:
                  playbookStates[
                    selectedPlaybook.id
                  ],
              }
            : null
        }
        onClose={() => setSelectedPlaybook(null)}
        onRun={openExecution}
      />

      {runningPlaybook && (
        <div className="playbook-execution-toast">
          <RefreshCw
            size={15}
            className="playbook-toast-spin"
          />

          <div>
            <strong>
              Executing response playbook
            </strong>

            <span>
              {runningPlaybook} · Response engine active
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export default Playbooks;