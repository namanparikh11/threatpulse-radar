import DashboardPage from './pages/DashboardPage';
import { WorkspaceProvider } from './state/WorkspaceContext';
import { EnvironmentProvider } from './state/EnvironmentContext';
import { RemediationProvider } from './state/RemediationContext';

export default function App() {
  return (
    <WorkspaceProvider>
      <EnvironmentProvider>
        <RemediationProvider>
          <DashboardPage />
        </RemediationProvider>
      </EnvironmentProvider>
    </WorkspaceProvider>
  );
}
