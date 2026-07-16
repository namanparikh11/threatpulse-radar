import DashboardPage from './pages/DashboardPage';
import { WorkspaceProvider } from './state/WorkspaceContext';

export default function App() {
  return (
    <WorkspaceProvider>
      <DashboardPage />
    </WorkspaceProvider>
  );
}
