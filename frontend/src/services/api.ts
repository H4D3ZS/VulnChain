import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add auth token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Workspaces
export const getWorkspaces = () => api.get('/api/workspaces/')
export const createWorkspace = (data: any) => api.post('/api/workspaces/', data)
export const deleteWorkspace = (id: string) => api.delete(`/api/workspaces/${id}`)

// Targets
export const getTargets = () => api.get('/api/targets/')
export const createTarget = (data: any) => api.post('/api/targets/', data)
export const updateTarget = (id: string, data: any) => api.put(`/api/targets/${id}`, data)
export const deleteTarget = (id: string) => api.delete(`/api/targets/${id}`)
export const getTarget = (id: string) => api.get(`/api/targets/${id}`)

// Modules
export const getModules = () => api.get('/api/modules/')
export const executeModule = (data: any) => api.post('/api/modules/execute', data)
export const getModuleExecutions = (targetId?: string) => {
  const params = targetId ? `?target_id=${targetId}` : ''
  return api.get(`/api/modules/executions${params}`)
}
export const getExecutionStatus = (executionId: string) => 
  api.get(`/api/modules/executions/${executionId}`)

// Findings
export const getFindings = (workspaceId?: string, severity?: string, vulnerabilityType?: string) => {
  const params = new URLSearchParams()
  if (workspaceId) params.append('workspace_id', workspaceId)
  if (severity) params.append('severity', severity)
  if (vulnerabilityType) params.append('vulnerability_type', vulnerabilityType)
  const queryString = params.toString()
  return api.get(`/api/findings/${queryString ? '?' + queryString : ''}`)
}
export const createFinding = (data: any) => api.post('/api/findings/', data)
export const getFinding = (id: string) => api.get(`/api/findings/${id}`)
export const updateFinding = (id: string, data: any) => api.put(`/api/findings/${id}`, data)
export const deleteFinding = (id: string) => api.delete(`/api/findings/${id}`)
export const getFindingEvidence = (findingId: string) => 
  api.get(`/api/findings/${findingId}/evidence`)

// Sessions
export const getSessions = (workspaceId?: number) => {
  const params = workspaceId ? `?workspace_id=${workspaceId}` : ''
  return api.get(`/api/sessions${params}`)
}

// Tasks
export const getTasks = () => api.get('/api/tasks')
export const getTaskStatus = (taskId: string) => api.get(`/api/tasks/status/${taskId}`)
export const startScan = (data: any) => api.post('/api/tasks/scan/reconnaissance', data)
export const startFuzzing = (data: any) => api.post('/api/tasks/fuzzing', data)

// Auth
export const login = (data: any) => api.post('/api/auth/login', data)
export const register = (data: any) => api.post('/api/auth/register', data)
export const logout = () => {
  localStorage.removeItem('token')
  return Promise.resolve()
}

// Health check
export const healthCheck = () => api.get('/health')

export default api
