import {
  Activity,
  Bell,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  Globe2,
  KeyRound,
  LockKeyhole,
  MonitorCog,
  Network,
  RefreshCw,
  Save,
  Server,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  X,
} from "lucide-react";
import { useState } from "react";

import SettingsStatusBadge from "../../components/settings/SettingsStatusBadge";

import "./Settings.css";

const INITIAL_SETTINGS = {
  telemetryInterval: "5",
  eventRetention: "30",
  timezone: "UTC",
  logLevel: "INFO",
  sessionTimeout: "30",
  maxLoginAttempts: "5",
  passwordRotation: "90",
  alertNotifications: true,
  criticalAlerts: true,
  emailNotifications: false,
  autoRefresh: true,
  threatIntelligence: true,
  analystAuditLog: true,
};

const SYSTEM_SERVICES = [
  {
    name: "Event Collector",
    description: "Security telemetry ingestion service",
    status: "OPERATIONAL",
    uptime: "99.98%",
    latency: "142 ms",
    icon: Activity,
  },
  {
    name: "Detection Engine",
    description: "Rule evaluation and threat detection",
    status: "OPERATIONAL",
    uptime: "99.94%",
    latency: "86 ms",
    icon: Shield,
  },
  {
    name: "Response Engine",
    description: "Automated containment and orchestration",
    status: "OPERATIONAL",
    uptime: "99.91%",
    latency: "118 ms",
    icon: Terminal,
  },
  {
    name: "Threat Intelligence",
    description: "IOC and intelligence synchronization",
    status: "OPERATIONAL",
    uptime: "99.87%",
    latency: "204 ms",
    icon: Globe2,
  },
  {
    name: "Database",
    description: "Security telemetry persistence layer",
    status: "OPERATIONAL",
    uptime: "99.99%",
    latency: "24 ms",
    icon: Database,
  },
  {
    name: "Authentication",
    description: "Identity and session management",
    status: "OPERATIONAL",
    uptime: "99.99%",
    latency: "31 ms",
    icon: LockKeyhole,
  },
];

const CONFIGURATION_GROUPS = [
  {
    id: "telemetry",
    label: "Telemetry",
    description: "Collection and event processing",
    icon: Activity,
  },
  {
    id: "security",
    label: "Security",
    description: "Authentication and access controls",
    icon: ShieldCheck,
  },
  {
    id: "notifications",
    label: "Notifications",
    description: "Alert and analyst notifications",
    icon: Bell,
  },
  {
    id: "system",
    label: "System",
    description: "Platform and interface behavior",
    icon: MonitorCog,
  },
];

function MetricCard({ icon: Icon, label, value, detail, tone }) {
  return (
    <article
      className={`settings-metric settings-metric--${tone}`}
    >
      <div className="settings-metric__top">
        <span className="settings-metric__icon">
          <Icon size={17} strokeWidth={1.9} />
        </span>

        <span className="settings-metric__label">
          {label}
        </span>
      </div>

      <strong className="settings-metric__value">
        {value}
      </strong>

      <span className="settings-metric__detail">
        {detail}
      </span>
    </article>
  );
}

function SettingToggle({
  label,
  description,
  checked,
  onChange,
}) {
  return (
    <div className="settings-toggle">
      <div className="settings-toggle__content">
        <strong>{label}</strong>
        <span>{description}</span>
      </div>

      <button
        type="button"
        className={`settings-toggle__switch ${
          checked
            ? "settings-toggle__switch--active"
            : ""
        }`}
        onClick={() => onChange(!checked)}
        role="switch"
        aria-checked={checked}
        aria-label={label}
      >
        <span />
      </button>
    </div>
  );
}

function SettingsField({
  label,
  description,
  value,
  onChange,
  options,
}) {
  return (
    <div className="settings-field">
      <div className="settings-field__label">
        <strong>{label}</strong>
        <span>{description}</span>
      </div>

      <select
        value={value}
        onChange={(event) =>
          onChange(event.target.value)
        }
      >
        {options.map((option) => (
          <option
            key={option.value}
            value={option.value}
          >
            {option.label}
          </option>
        ))}
      </select>

      <ChevronRight
        size={14}
        className="settings-field__chevron"
      />
    </div>
  );
}

function NumberField({
  label,
  description,
  value,
  onChange,
  suffix,
}) {
  return (
    <label className="settings-number-field">
      <span className="settings-number-field__content">
        <strong>{label}</strong>
        <small>{description}</small>
      </span>

      <span className="settings-number-field__input">
        <input
          type="number"
          min="1"
          value={value}
          onChange={(event) =>
            onChange(event.target.value)
          }
        />

        <span>{suffix}</span>
      </span>
    </label>
  );
}

function ServiceRow({ service }) {
  const Icon = service.icon;

  return (
    <article className="settings-service">
      <div className="settings-service__icon">
        <Icon size={17} strokeWidth={1.8} />
      </div>

      <div className="settings-service__identity">
        <strong>{service.name}</strong>
        <span>{service.description}</span>
      </div>

      <div className="settings-service__metric">
        <span>UPTIME</span>
        <strong>{service.uptime}</strong>
      </div>

      <div className="settings-service__metric">
        <span>LATENCY</span>
        <strong>{service.latency}</strong>
      </div>

      <SettingsStatusBadge status={service.status} />
    </article>
  );
}

function Settings() {
  const [settings, setSettings] =
    useState(INITIAL_SETTINGS);

  const [activeGroup, setActiveGroup] =
    useState("telemetry");

  const [saved, setSaved] = useState(false);

  const updateSetting = (key, value) => {
    setSettings((current) => ({
      ...current,
      [key]: value,
    }));

    setSaved(false);
  };

  const saveSettings = () => {
    setSaved(true);

    window.setTimeout(() => {
      setSaved(false);
    }, 2200);
  };

  const resetSettings = () => {
    setSettings(INITIAL_SETTINGS);
    setSaved(false);
  };

  const renderConfiguration = () => {
    if (activeGroup === "telemetry") {
      return (
        <div className="settings-config">
          <div className="settings-config__header">
            <div>
              <span className="settings-section-kicker">
                <Activity size={13} />
                TELEMETRY CONFIGURATION
              </span>

              <h2>Collection & Processing</h2>

              <p>
                Configure how security events are
                collected, processed and retained.
              </p>
            </div>
          </div>

          <div className="settings-config__grid">
            <NumberField
              label="Telemetry Refresh"
              description="Dashboard telemetry refresh interval"
              value={settings.telemetryInterval}
              onChange={(value) =>
                updateSetting(
                  "telemetryInterval",
                  value,
                )
              }
              suffix="SEC"
            />

            <NumberField
              label="Event Retention"
              description="Security event retention period"
              value={settings.eventRetention}
              onChange={(value) =>
                updateSetting(
                  "eventRetention",
                  value,
                )
              }
              suffix="DAYS"
            />

            <SettingsField
              label="Log Level"
              description="Minimum application log severity"
              value={settings.logLevel}
              onChange={(value) =>
                updateSetting("logLevel", value)
              }
              options={[
                {
                  value: "DEBUG",
                  label: "DEBUG",
                },
                {
                  value: "INFO",
                  label: "INFO",
                },
                {
                  value: "WARNING",
                  label: "WARNING",
                },
                {
                  value: "ERROR",
                  label: "ERROR",
                },
              ]}
            />

            <SettingsField
              label="System Timezone"
              description="Default platform timezone"
              value={settings.timezone}
              onChange={(value) =>
                updateSetting("timezone", value)
              }
              options={[
                {
                  value: "UTC",
                  label: "UTC",
                },
                {
                  value: "IST",
                  label: "Asia/Kolkata",
                },
                {
                  value: "EST",
                  label: "America/New_York",
                },
                {
                  value: "GMT",
                  label: "Europe/London",
                },
              ]}
            />
          </div>

          <div className="settings-info-strip">
            <Database size={15} />

            <div>
              <strong>
                TELEMETRY PIPELINE STATUS
              </strong>

              <span>
                Collectors are operational and
                processing events within normal latency
                thresholds.
              </span>
            </div>

            <SettingsStatusBadge status="OPERATIONAL" />
          </div>
        </div>
      );
    }

    if (activeGroup === "security") {
      return (
        <div className="settings-config">
          <div className="settings-config__header">
            <div>
              <span className="settings-section-kicker">
                <ShieldCheck size={13} />
                SECURITY CONFIGURATION
              </span>

              <h2>Authentication & Access</h2>

              <p>
                Configure account protection and
                security session policies.
              </p>
            </div>
          </div>

          <div className="settings-config__grid">
            <NumberField
              label="Session Timeout"
              description="Inactive session expiration"
              value={settings.sessionTimeout}
              onChange={(value) =>
                updateSetting(
                  "sessionTimeout",
                  value,
                )
              }
              suffix="MIN"
            />

            <NumberField
              label="Maximum Login Attempts"
              description="Failed attempts before lockout"
              value={settings.maxLoginAttempts}
              onChange={(value) =>
                updateSetting(
                  "maxLoginAttempts",
                  value,
                )
              }
              suffix="TRIES"
            />

            <NumberField
              label="Password Rotation"
              description="Required password rotation interval"
              value={settings.passwordRotation}
              onChange={(value) =>
                updateSetting(
                  "passwordRotation",
                  value,
                )
              }
              suffix="DAYS"
            />
          </div>

          <div className="settings-security-summary">
            <div>
              <KeyRound size={16} />
              <span>
                <strong>AUTHENTICATION POLICY</strong>
                <small>
                  Enterprise security controls enabled
                </small>
              </span>
            </div>

            <div>
              <LockKeyhole size={16} />
              <span>
                <strong>SESSION PROTECTION</strong>
                <small>
                  Automatic session timeout enabled
                </small>
              </span>
            </div>

            <div>
              <ShieldCheck size={16} />
              <span>
                <strong>ACCESS CONTROL</strong>
                <small>
                  Role-based permissions enforced
                </small>
              </span>
            </div>
          </div>
        </div>
      );
    }

    if (activeGroup === "notifications") {
      return (
        <div className="settings-config">
          <div className="settings-config__header">
            <div>
              <span className="settings-section-kicker">
                <Bell size={13} />
                NOTIFICATION CONFIGURATION
              </span>

              <h2>Alert & Analyst Notifications</h2>

              <p>
                Control which security events generate
                analyst-facing notifications.
              </p>
            </div>
          </div>

          <div className="settings-toggle-list">
            <SettingToggle
              label="Security Alert Notifications"
              description="Notify analysts when new security alerts are generated."
              checked={settings.alertNotifications}
              onChange={(value) =>
                updateSetting(
                  "alertNotifications",
                  value,
                )
              }
            />

            <SettingToggle
              label="Critical Alert Escalation"
              description="Immediately escalate critical security events."
              checked={settings.criticalAlerts}
              onChange={(value) =>
                updateSetting(
                  "criticalAlerts",
                  value,
                )
              }
            />

            <SettingToggle
              label="Email Notifications"
              description="Send selected security notifications through email."
              checked={settings.emailNotifications}
              onChange={(value) =>
                updateSetting(
                  "emailNotifications",
                  value,
                )
              }
            />

            <SettingToggle
              label="Analyst Audit Logging"
              description="Record analyst actions for security auditing."
              checked={settings.analystAuditLog}
              onChange={(value) =>
                updateSetting(
                  "analystAuditLog",
                  value,
                )
              }
            />
          </div>
        </div>
      );
    }

    return (
      <div className="settings-config">
        <div className="settings-config__header">
          <div>
            <span className="settings-section-kicker">
              <MonitorCog size={13} />
              SYSTEM CONFIGURATION
            </span>

            <h2>Platform Behavior</h2>

            <p>
              Configure interface and automated
              platform behavior.
            </p>
          </div>
        </div>

        <div className="settings-toggle-list">
          <SettingToggle
            label="Automatic Dashboard Refresh"
            description="Keep dashboard telemetry synchronized automatically."
            checked={settings.autoRefresh}
            onChange={(value) =>
              updateSetting("autoRefresh", value)
            }
          />

          <SettingToggle
            label="Threat Intelligence Synchronization"
            description="Keep IOC intelligence synchronized with the defense node."
            checked={settings.threatIntelligence}
            onChange={(value) =>
              updateSetting(
                "threatIntelligence",
                value,
              )
            }
          />
        </div>

        <div className="settings-system-info">
          <div>
            <Server size={16} />
            <span>
              <strong>DEFENSE NODE</strong>
              <small>CYBERDEFENSE-X / SOC-CORE-01</small>
            </span>
          </div>

          <div>
            <Network size={16} />
            <span>
              <strong>NETWORK MODE</strong>
              <small>LOCAL / SECURE</small>
            </span>
          </div>

          <div>
            <Clock3 size={16} />
            <span>
              <strong>SYSTEM TIME</strong>
              <small>UTC SYNCHRONIZED</small>
            </span>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="settings-page">
      <header className="settings-page__header">
        <div>
          <div className="settings-breadcrumb">
            CYBERDEFENSE-X
            <span>/</span>
            SOC
            <span>/</span>
            ADMINISTRATION
            <span>/</span>
            SETTINGS
          </div>

          <div className="settings-title-row">
            <div>
              <div className="settings-eyebrow">
                <SlidersHorizontal size={13} />
                PLATFORM CONFIGURATION
              </div>

              <h1>System Settings</h1>

              <p>
                Configure security operations,
                telemetry, authentication and platform
                behavior.
              </p>
            </div>

            <div className="settings-security-status">
              <span className="settings-security-status__icon">
                <ShieldCheck size={19} />
              </span>

              <div>
                <strong>SECURITY BASELINE</strong>
                <span>POLICY ENFORCED</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      <section className="settings-metrics">
        <MetricCard
          icon={Server}
          label="Platform Status"
          value="ONLINE"
          detail="All core services operational"
          tone="success"
        />

        <MetricCard
          icon={ShieldCheck}
          label="Security Baseline"
          value="100%"
          detail="Configuration compliant"
          tone="cyan"
        />

        <MetricCard
          icon={Database}
          label="Event Retention"
          value={`${settings.eventRetention}D`}
          detail="Configured retention period"
          tone="warning"
        />

        <MetricCard
          icon={Activity}
          label="Telemetry"
          value={`${settings.telemetryInterval}S`}
          detail="Current refresh interval"
          tone="success"
        />
      </section>

      <section className="settings-workspace">
        <aside className="settings-sidebar">
          <div className="settings-sidebar__header">
            <span>CONFIGURATION</span>
            <small>4 MODULES</small>
          </div>

          <nav className="settings-nav">
            {CONFIGURATION_GROUPS.map((group) => {
              const Icon = group.icon;
              const active =
                activeGroup === group.id;

              return (
                <button
                  type="button"
                  key={group.id}
                  className={
                    active
                      ? "settings-nav__item settings-nav__item--active"
                      : "settings-nav__item"
                  }
                  onClick={() =>
                    setActiveGroup(group.id)
                  }
                >
                  <span className="settings-nav__icon">
                    <Icon size={16} />
                  </span>

                  <span className="settings-nav__content">
                    <strong>{group.label}</strong>
                    <small>{group.description}</small>
                  </span>

                  <ChevronRight size={14} />
                </button>
              );
            })}
          </nav>

          <div className="settings-sidebar__status">
            <span className="settings-sidebar__status-dot" />

            <div>
              <strong>CONFIGURATION SAFE</strong>
              <span>
                No pending critical changes
              </span>
            </div>
          </div>
        </aside>

        <main className="settings-main">
          {renderConfiguration()}
        </main>
      </section>

      <section className="settings-services">
        <div className="settings-services__header">
          <div>
            <span className="settings-section-kicker">
              <Server size={13} />
              INFRASTRUCTURE
            </span>

            <h2>Service Health</h2>

            <p>
              Current operational status of core
              CYBERDEFENSE-X services.
            </p>
          </div>

          <span className="settings-services__updated">
            <RefreshCw size={12} />
            LIVE STATUS
          </span>
        </div>

        <div className="settings-services__list">
          {SYSTEM_SERVICES.map((service) => (
            <ServiceRow
              key={service.name}
              service={service}
            />
          ))}
        </div>
      </section>

      <div className="settings-actions">
        <div className="settings-actions__info">
          <LockKeyhole size={14} />

          <span>
            Changes are applied to the local defense
            node configuration.
          </span>
        </div>

        <div className="settings-actions__buttons">
          <button
            type="button"
            className="settings-button settings-button--secondary"
            onClick={resetSettings}
          >
            <RefreshCw size={14} />
            Reset
          </button>

          <button
            type="button"
            className="settings-button settings-button--primary"
            onClick={saveSettings}
          >
            {saved ? (
              <>
                <Check size={14} />
                Saved
              </>
            ) : (
              <>
                <Save size={14} />
                Save Configuration
              </>
            )}
          </button>
        </div>
      </div>

      {saved && (
        <div className="settings-save-toast">
          <CheckCircle2 size={16} />

          <div>
            <strong>Configuration saved</strong>
            <span>
              Security settings updated successfully.
            </span>
          </div>

          <button
            type="button"
            onClick={() => setSaved(false)}
            aria-label="Dismiss notification"
          >
            <X size={14} />
          </button>
        </div>
      )}

      <footer className="settings-footer">
        <div>
          <span className="settings-footer__pulse" />
          CONFIGURATION SERVICE ONLINE
        </div>

        <span>
          POLICY <strong>ENFORCED</strong>
        </span>

        <span>
          NODE <strong>SOC-CORE-01</strong>
        </span>

        <span>
          CONFIG VERSION <strong>v4.2</strong>
        </span>
      </footer>
    </div>
  );
}

export default Settings;