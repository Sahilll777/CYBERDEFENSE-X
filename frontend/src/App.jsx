import { Navigate, Route, Routes } from "react-router-dom";

import AppShell from "./components/layout/AppShell";

import Dashboard from "./pages/Dashboard/Dashboard";
import Alerts from "./pages/Alerts/Alerts";
import Detections from "./pages/Detections/Detections";
import Incidents from "./pages/Incidents/Incidents";
import Events from "./pages/Events/Events";
import Playbooks from "./pages/Playbooks/Playbooks";
import Users from "./pages/Users/Users";
import Settings from "./pages/Settings/Settings";

function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        {/* =====================================================
            DASHBOARD
            ===================================================== */}
        <Route
          path="/"
          element={<Dashboard />}
        />

        {/* =====================================================
            DETECTION
            ===================================================== */}
        <Route
          path="/alerts"
          element={<Alerts />}
        />

        <Route
          path="/detections"
          element={<Detections />}
        />

        {/* =====================================================
            RESPONSE
            ===================================================== */}
        <Route
          path="/incidents"
          element={<Incidents />}
        />

        <Route
          path="/playbooks"
          element={<Playbooks />}
        />

        {/* =====================================================
            TELEMETRY
            ===================================================== */}
        <Route
          path="/events"
          element={<Events />}
        />

        {/* =====================================================
            ADMINISTRATION
            ===================================================== */}
        <Route
          path="/users"
          element={<Users />}
        />

        <Route
          path="/settings"
          element={<Settings />}
        />

        {/* =====================================================
            FALLBACK
            ===================================================== */}
        <Route
          path="*"
          element={<Navigate to="/" replace />}
        />
      </Route>
    </Routes>
  );
}

export default App;