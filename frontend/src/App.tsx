import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import SimpleLayout from './components/SimpleLayout'
import Dashboard from './components/Dashboard'
import WorkspaceManager from './components/WorkspaceManager'
import TargetConfig from './components/TargetConfig'
import ModuleSelector from './components/ModuleSelector'
import FindingsDashboard from './components/FindingsDashboard'
import FuzzingMonitor from './components/FuzzingMonitor'
import JWTInspector from './components/JWTInspector'
import OOBListener from './components/OOBListener'
import LogViewer from './components/LogViewer'

const queryClient = new QueryClient()

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <SimpleLayout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/workspaces" element={<WorkspaceManager />} />
            <Route path="/targets" element={<TargetConfig />} />
            <Route path="/modules" element={<ModuleSelector />} />
            <Route path="/findings" element={<FindingsDashboard />} />
            <Route path="/fuzzing" element={<FuzzingMonitor />} />
            <Route path="/jwt" element={<JWTInspector />} />
            <Route path="/oob" element={<OOBListener />} />
            <Route path="/logs" element={<LogViewer />} />
          </Routes>
        </SimpleLayout>
      </Router>
    </QueryClientProvider>
  )
}

export default App
