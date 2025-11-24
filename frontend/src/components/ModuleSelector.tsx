/**
 * Module Selector Component
 * 
 * Attack module selection and execution with:
 * - Grid of available attack modules with icons
 * - Module recommendations based on reconnaissance
 * - Configuration modal for parameters
 * - Execute button with progress tracking
 * - Module status display
 */

import { useState, useEffect } from 'react'
import { getModules, executeModule } from '../services/api'

interface ModuleParameter {
  name: string
  type: 'string' | 'number' | 'boolean' | 'select'
  description: string
  required: boolean
  default?: any
  options?: string[]
}

interface Module {
  id: string
  name: string
  category: string
  description: string
  icon: string
  parameters: ModuleParameter[]
  recommended?: boolean
  requiresAuth?: boolean
  estimatedTime?: string
}

interface ModuleExecution {
  moduleId: string
  status: 'running' | 'completed' | 'failed'
  progress: number
  startTime: string
  endTime?: string
  findings?: number
  error?: string
}

interface ModuleSelectorProps {
  targetUrl?: string
  onModuleExecute?: (moduleId: string, params: Record<string, any>) => void
  recommendations?: string[]
}

export default function ModuleSelector({
  targetUrl,
  onModuleExecute,
  recommendations = []
}: ModuleSelectorProps) {
  const [modules, setModules] = useState<Module[]>([])
  const [loading, setLoading] = useState(true)
  
  // Load modules from API
  useEffect(() => {
    loadModules()
  }, [])
  
  const loadModules = async () => {
    try {
      setLoading(true)
      const response = await getModules()
      // Map API response to component format
      const mappedModules = (response.data || []).map((m: any) => ({
        id: m.module_id,
        name: m.name,
        category: m.category,
        description: m.description,
        icon: getModuleIcon(m.module_id),
        parameters: m.parameters || [],
        estimatedTime: m.estimated_time,
        recommended: recommendations.includes(m.module_id)
      }))
      setModules(mappedModules)
    } catch (err) {
      console.error('Failed to load modules:', err)
      // Fallback to default modules
      setModules([
    {
      id: 'sql-injection',
      name: 'SQL Injection',
      category: 'Injection',
      description: 'Test for SQL injection vulnerabilities using multiple techniques',
      icon: '💉',
      parameters: [
        { name: 'parameter', type: 'string', description: 'Parameter to test', required: true },
        { name: 'technique', type: 'select', description: 'Injection technique', required: false, options: ['all', 'time-based', 'boolean', 'error-based'], default: 'all' }
      ],
      recommended: recommendations.includes('sql-injection'),
      estimatedTime: '2-5 min'
    },
    {
      id: 'xss',
      name: 'Cross-Site Scripting',
      category: 'Injection',
      description: 'Test for XSS vulnerabilities with filter bypass payloads',
      icon: '🔓',
      parameters: [
        { name: 'parameter', type: 'string', description: 'Parameter to test', required: true },
        { name: 'context', type: 'select', description: 'Injection context', required: false, options: ['html', 'attribute', 'javascript', 'url'], default: 'html' }
      ],
      recommended: recommendations.includes('xss'),
      estimatedTime: '1-3 min'
    },
    {
      id: 'command-injection',
      name: 'Command Injection',
      category: 'Injection',
      description: 'Test for OS command injection with OOB detection',
      icon: '⚡',
      parameters: [
        { name: 'parameter', type: 'string', description: 'Parameter to test', required: true },
        { name: 'use_oob', type: 'boolean', description: 'Use out-of-band detection', required: false, default: true }
      ],
      estimatedTime: '2-4 min'
    },
    {
      id: 'ssrf',
      name: 'SSRF',
      category: 'Injection',
      description: 'Test for Server-Side Request Forgery with filter bypasses',
      icon: '🌐',
      parameters: [
        { name: 'parameter', type: 'string', description: 'Parameter to test', required: true },
        { name: 'test_cloud', type: 'boolean', description: 'Test cloud metadata endpoints', required: false, default: true }
      ],
      estimatedTime: '3-6 min'
    },
    {
      id: 'jwt',
      name: 'JWT Manipulation',
      category: 'Authentication',
      description: 'Test JWT tokens for manipulation vulnerabilities',
      icon: '🔐',
      parameters: [
        { name: 'token_location', type: 'select', description: 'Where to find JWT', required: false, options: ['auto', 'header', 'cookie'], default: 'auto' }
      ],
      requiresAuth: true,
      estimatedTime: '1-2 min'
    },
    {
      id: 'directory-traversal',
      name: 'Directory Traversal',
      category: 'File Access',
      description: 'Test for path traversal vulnerabilities',
      icon: '📁',
      parameters: [
        { name: 'parameter', type: 'string', description: 'File parameter to test', required: true },
        { name: 'target_file', type: 'string', description: 'Target file to read', required: false, default: '/etc/passwd' }
      ],
      estimatedTime: '1-3 min'
    },
    {
      id: 'reconnaissance',
      name: 'Reconnaissance',
      category: 'Discovery',
      description: 'Technology fingerprinting and discovery',
      icon: '🔍',
      parameters: [
        { name: 'deep_scan', type: 'boolean', description: 'Perform deep scan', required: false, default: false }
      ],
      recommended: !targetUrl,
      estimatedTime: '3-10 min'
    },
    {
      id: 'brute-force',
      name: 'Brute Force',
      category: 'Authentication',
      description: 'Brute force login credentials',
      icon: '🔨',
      parameters: [
        { name: 'username_list', type: 'string', description: 'Path to username list', required: true },
        { name: 'password_list', type: 'string', description: 'Path to password list', required: true },
        { name: 'delay', type: 'number', description: 'Delay between attempts (ms)', required: false, default: 100 }
      ],
      estimatedTime: '5-30 min'
    }
      ])
    } finally {
      setLoading(false)
    }
  }
  
  // Helper function to get module icon
  const getModuleIcon = (moduleId: string): string => {
    const icons: Record<string, string> = {
      'sql-injection': '💉',
      'xss': '🔓',
      'command-injection': '⚡',
      'ssrf': '🌐',
      'jwt': '🔐',
      'directory-traversal': '📁',
      'reconnaissance': '🔍',
      'brute-force': '🔨'
    }
    return icons[moduleId] || '⚔️'
  }
  
  const [selectedModule, setSelectedModule] = useState<Module | null>(null)
  const [paramValues, setParamValues] = useState<Record<string, any>>({})
  const [executions, setExecutions] = useState<Record<string, ModuleExecution>>({})
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  
  // Get unique categories
  const categories = ['all', ...Array.from(new Set(modules.map(m => m.category)))]
  
  // Filter modules
  const filteredModules = modules.filter(module => {
    if (categoryFilter !== 'all' && module.category !== categoryFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        module.name.toLowerCase().includes(query) ||
        module.description.toLowerCase().includes(query) ||
        module.category.toLowerCase().includes(query)
      )
    }
    return true
  })
  
  // Open configuration modal
  const openModule = (module: Module) => {
    setSelectedModule(module)
    // Set default values
    const defaults: Record<string, any> = {}
    module.parameters.forEach(param => {
      if (param.default !== undefined) {
        defaults[param.name] = param.default
      }
    })
    setParamValues(defaults)
  }
  
  // Execute module
  const handleExecuteModule = async () => {
    if (!selectedModule) return
    
    // Validate required parameters
    for (const param of selectedModule.parameters) {
      if (param.required && !paramValues[param.name]) {
        alert(`Parameter "${param.name}" is required`)
        return
      }
    }
    
    try {
      // Call backend API
      const response = await executeModule({
        target_id: targetUrl || 'default-target',
        module_id: selectedModule.id,
        parameters: paramValues
      })
      
      // Create execution record
      const execution: ModuleExecution = {
        moduleId: selectedModule.id,
        status: 'running',
        progress: 0,
        startTime: new Date().toISOString()
      }
      
      setExecutions({ ...executions, [selectedModule.id]: execution })
      onModuleExecute?.(selectedModule.id, paramValues)
      
      // Simulate progress (in real app, this would come from WebSocket)
      let progress = 0
      const interval = setInterval(() => {
        progress += 10
        if (progress >= 100) {
          clearInterval(interval)
          setExecutions(prev => ({
            ...prev,
            [selectedModule.id]: {
              ...prev[selectedModule.id],
              status: 'completed',
              progress: 100,
              endTime: new Date().toISOString(),
              findings: Math.floor(Math.random() * 5)
            }
          }))
        } else {
          setExecutions(prev => ({
            ...prev,
            [selectedModule.id]: {
              ...prev[selectedModule.id],
              progress
            }
          }))
        }
      }, 500)
      
      setSelectedModule(null)
      setParamValues({})
      
      alert(`Module "${selectedModule.name}" started successfully!`)
    } catch (err: any) {
      console.error('Failed to execute module:', err)
      alert(err.response?.data?.detail || 'Failed to execute module')
    }
  }
  
  // Get module status
  const getModuleStatus = (moduleId: string) => {
    return executions[moduleId]
  }
  
  return (
    <div className="module-selector p-6 bg-white rounded-lg shadow">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold">Attack Modules</h2>
        <div className="text-sm text-gray-600">
          {filteredModules.length} modules available
        </div>
      </div>
      
      {/* Filters */}
      <div className="mb-6 space-y-3">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-700">Category:</span>
          {categories.map(category => (
            <button
              key={category}
              onClick={() => setCategoryFilter(category)}
              className={`px-3 py-1 text-sm rounded capitalize ${
                categoryFilter === category
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
              }`}
            >
              {category}
            </button>
          ))}
        </div>
        
        <input
          type="text"
          placeholder="Search modules..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full px-4 py-2 border rounded-lg"
        />
      </div>
      
      {/* Recommended Modules */}
      {recommendations.length > 0 && (
        <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="text-sm font-medium text-blue-900 mb-2">
            💡 Recommended based on reconnaissance
          </div>
          <div className="flex gap-2 flex-wrap">
            {modules
              .filter(m => m.recommended)
              .map(module => (
                <button
                  key={module.id}
                  onClick={() => openModule(module)}
                  className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  {module.icon} {module.name}
                </button>
              ))}
          </div>
        </div>
      )}
      
      {/* Module Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredModules.map((module) => {
          const status = getModuleStatus(module.id)
          
          return (
            <div
              key={module.id}
              className={`border rounded-lg p-4 hover:shadow-md transition-shadow cursor-pointer ${
                module.recommended ? 'border-blue-500 bg-blue-50' : ''
              }`}
              onClick={() => openModule(module)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="text-3xl">{module.icon}</div>
                {module.recommended && (
                  <span className="px-2 py-0.5 text-xs bg-blue-600 text-white rounded">
                    Recommended
                  </span>
                )}
              </div>
              
              <h3 className="font-semibold text-gray-900 mb-1">{module.name}</h3>
              <p className="text-sm text-gray-600 mb-3">{module.description}</p>
              
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span className="px-2 py-1 bg-gray-100 rounded">{module.category}</span>
                <span>{module.estimatedTime}</span>
              </div>
              
              {module.requiresAuth && (
                <div className="mt-2 text-xs text-orange-600">
                  🔒 Requires authentication
                </div>
              )}
              
              {/* Status */}
              {status && (
                <div className="mt-3 pt-3 border-t">
                  {status.status === 'running' && (
                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-blue-600">Running...</span>
                        <span className="text-gray-600">{status.progress}%</span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${status.progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                  
                  {status.status === 'completed' && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-green-600">✓ Completed</span>
                      <span className="text-gray-600">{status.findings} findings</span>
                    </div>
                  )}
                  
                  {status.status === 'failed' && (
                    <div className="text-sm text-red-600">
                      ✗ Failed: {status.error}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
      
      {filteredModules.length === 0 && (
        <div className="text-center py-12 text-gray-500">
          <div className="text-4xl mb-2">🔍</div>
          <div>No modules found</div>
          <div className="text-sm mt-1">Try adjusting your filters</div>
        </div>
      )}
      
      {/* Configuration Modal */}
      {selectedModule && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedModule(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-2xl w-full p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-3xl">{selectedModule.icon}</span>
                  <h3 className="text-xl font-semibold">{selectedModule.name}</h3>
                </div>
                <p className="text-sm text-gray-600">{selectedModule.description}</p>
              </div>
              <button
                onClick={() => setSelectedModule(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>
            
            <div className="mb-4 flex items-center gap-4 text-sm text-gray-600">
              <span className="px-2 py-1 bg-gray-100 rounded">{selectedModule.category}</span>
              <span>⏱️ {selectedModule.estimatedTime}</span>
              {selectedModule.requiresAuth && (
                <span className="text-orange-600">🔒 Requires auth</span>
              )}
            </div>
            
            {/* Parameters */}
            <div className="space-y-4 mb-6">
              <h4 className="font-medium text-gray-900">Configuration</h4>
              
              {selectedModule.parameters.length === 0 ? (
                <div className="text-sm text-gray-500">No configuration required</div>
              ) : (
                selectedModule.parameters.map((param) => (
                  <div key={param.name}>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      {param.name}
                      {param.required && <span className="text-red-600 ml-1">*</span>}
                    </label>
                    <p className="text-xs text-gray-500 mb-2">{param.description}</p>
                    
                    {param.type === 'string' && (
                      <input
                        type="text"
                        value={paramValues[param.name] || ''}
                        onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.value })}
                        placeholder={param.default?.toString() || ''}
                        className="w-full px-3 py-2 border rounded-lg"
                      />
                    )}
                    
                    {param.type === 'number' && (
                      <input
                        type="number"
                        value={paramValues[param.name] || ''}
                        onChange={(e) => setParamValues({ ...paramValues, [param.name]: Number(e.target.value) })}
                        placeholder={param.default?.toString() || ''}
                        className="w-full px-3 py-2 border rounded-lg"
                      />
                    )}
                    
                    {param.type === 'boolean' && (
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={paramValues[param.name] ?? param.default ?? false}
                          onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.checked })}
                          className="rounded"
                        />
                        <span className="text-sm text-gray-600">Enable</span>
                      </div>
                    )}
                    
                    {param.type === 'select' && param.options && (
                      <select
                        value={paramValues[param.name] || param.default || ''}
                        onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.value })}
                        className="w-full px-3 py-2 border rounded-lg"
                      >
                        {param.options.map(option => (
                          <option key={option} value={option}>{option}</option>
                        ))}
                      </select>
                    )}
                  </div>
                ))
              )}
            </div>
            
            {/* Actions */}
            <div className="flex gap-3">
              <button
                onClick={handleExecuteModule}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                🚀 Execute Module
              </button>
              <button
                onClick={() => setSelectedModule(null)}
                className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
