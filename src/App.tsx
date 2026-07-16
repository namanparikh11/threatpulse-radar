import DashboardPage from './pages/DashboardPage';
import { WorkspaceProvider } from './state/WorkspaceContext';
import { EnvironmentProvider } from './state/EnvironmentContext';

export default function App() {
  return (
    <WorkspaceProvider>
      <EnvironmentProvider>
        <DashboardPage />
      </EnvironmentProvider>
    </WorkspaceProvider>
  );
}
