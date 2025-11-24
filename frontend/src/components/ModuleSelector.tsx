/**
 * Module Selector Component
 * 
 * Displays all 22 attack modules in a grid with:
 * - Category filtering
 * - Search functionality
 * - Module execution with parameters
 * - Real-time status tracking
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
  estimatedTime?: string
}

export default function ModuleSelector() {
  const [modules, setModules] = useState<Module[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedModule, setSelectedModule] = useState<Module | null>(null)
  const [paramValues, setParamValues] = useState<Record<string, any>>({})
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [executing, setExecuting] = useState<string | null>(null)

  // Load modules from API
  useEffect(() => {
    loadModules()
  }, [])

  const loadModules = async () => {
    try {
      setLoading(true)
      const response = await getModules()
      const mappedModules = (response.data || []).map((m: any) => ({
        id: m.module_id,
        name: m.name,
        category: m.category,
        description: m.description,
        icon: getModuleIcon(m.module_id),
        parameters: m.parameters || [],
        estimatedTime: m.estimated_time
      }))
      setModules(mappedModules)
    } catch (err) {
      console.error('Failed to load modules:', err)
    } finally {
      setLoading(false)
    }
  }

  // Helper function to get module icon
  const getModuleIcon = (moduleId: string): string => {
    const icons: Record<string, string> = {
      // Injection
      'sql-injection': '💉',
      'command-injection': '⚡',
      'nosql-injection': '🗄️',
      'ssrf': '🌐',
      'xxe': '📄',
      'ssti': '🎨',
      'xss': '🔓',

      // Auth
      'jwt': '🔐',
      'jwt-manipulation': '🔐',
      'csrf': '🎭',
      'oauth': '🔑',
      'oauth-saml': '🔑',
      'brute-force': '🔨',

      // File
      'file-upload': '📤',
      'file-upload-bypass': '📤',
      'directory-traversal': '📁',
      'deserialization': '📦',
      'prototype-pollution': '🧬',

      // Network
      'cors': '🔀',
      'cors-exploitation': '🔀',
      'cache-poisoning': '💾',
      'websocket': '🔌',
      'websocket-sse': '🔌',
      'race-condition': '🏃',

      // Discovery
      'reconnaissance': '🔍',
      'quick-scan': '⚡',
      'api-testing': '🔧',
      'headless-browser': '🤖',
      'ml-exploitation': '🧠',
      'cms-scanner': '📝'
    }
    return icons[moduleId] || '⚔️'
  }

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
      setExecuting(selectedModule.id)

      await executeModule({
        target_id: 'target-1', // TODO: Get from context
        module_id: selectedModule.id,
        parameters: paramValues
      })

      setSelectedModule(null)
      setParamValues({})
      alert(`Module "${selectedModule.name}" started successfully! Check the Findings page for results.`)
    } catch (err: any) {
      console.error('Failed to execute module:', err)
      alert(err.response?.data?.detail || 'Failed to execute module')
    } finally {
      setExecuting(null)
    }
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner"></div>
        <p>Loading modules...</p>
      </div>
    )
  }

  return (
    <div className="module-selector">
      <div className="module-header">
        <h2>Attack Modules</h2>
        <div className="module-count">
          {filteredModules.length} of {modules.length} modules
        </div>
      </div>

      {/* Filters */}
      <div className="module-filters">
        <div className="filter-group">
          <span className="filter-label">Category:</span>
          <div className="filter-buttons">
            {categories.map(category => (
              <button
                key={category}
                onClick={() => setCategoryFilter(category)}
                className={`filter-btn ${categoryFilter === category ? 'active' : ''}`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        <input
          type="text"
          placeholder="Search modules..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
      </div>

      {/* Module Grid */}
      <div className="module-grid">
        {filteredModules.map((module) => (
          <div
            key={module.id}
            className="module-card"
            onClick={() => openModule(module)}
          >
            <div className="module-card-header">
              <div className="module-icon">{module.icon}</div>
            </div>

            <h3 className="module-name">{module.name}</h3>
            <p className="module-description">{module.description}</p>

            <div className="module-meta">
              <span className="module-category">{module.category}</span>
              {module.estimatedTime && (
                <span className="module-time">⏱️ {module.estimatedTime}</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {filteredModules.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <div className="empty-title">No modules found</div>
          <div className="empty-subtitle">Try adjusting your filters</div>
        </div>
      )}

      {/* Configuration Modal */}
      {selectedModule && (
        <div className="modal-overlay" onClick={() => setSelectedModule(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <div className="modal-title-row">
                  <span className="modal-icon">{selectedModule.icon}</span>
                  <h3>{selectedModule.name}</h3>
                </div>
                <p className="modal-description">{selectedModule.description}</p>
              </div>
              <button
                onClick={() => setSelectedModule(null)}
                className="modal-close"
              >
                ✕
              </button>
            </div>

            <div className="modal-meta">
              <span className="meta-badge">{selectedModule.category}</span>
              {selectedModule.estimatedTime && (
                <span>⏱️ {selectedModule.estimatedTime}</span>
              )}
            </div>

            {/* Parameters */}
            <div className="modal-params">
              <h4>Configuration</h4>

              {selectedModule.parameters.length === 0 ? (
                <div className="no-params">No configuration required</div>
              ) : (
                <div className="params-list">
                  {selectedModule.parameters.map((param) => (
                    <div key={param.name} className="param-field">
                      <label>
                        {param.name}
                        {param.required && <span className="required">*</span>}
                      </label>
                      <p className="param-description">{param.description}</p>

                      {param.type === 'string' && (
                        <input
                          type="text"
                          value={paramValues[param.name] || ''}
                          onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.value })}
                          placeholder={param.default?.toString() || ''}
                          className="param-input"
                        />
                      )}

                      {param.type === 'number' && (
                        <input
                          type="number"
                          value={paramValues[param.name] || ''}
                          onChange={(e) => setParamValues({ ...paramValues, [param.name]: Number(e.target.value) })}
                          placeholder={param.default?.toString() || ''}
                          className="param-input"
                        />
                      )}

                      {param.type === 'boolean' && (
                        <div className="param-checkbox">
                          <input
                            type="checkbox"
                            checked={paramValues[param.name] ?? param.default ?? false}
                            onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.checked })}
                          />
                          <span>Enable</span>
                        </div>
                      )}

                      {param.type === 'select' && param.options && (
                        <select
                          value={paramValues[param.name] || param.default || ''}
                          onChange={(e) => setParamValues({ ...paramValues, [param.name]: e.target.value })}
                          className="param-select"
                        >
                          {param.options.map(option => (
                            <option key={option} value={option}>{option}</option>
                          ))}
                        </select>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Actions */}
            <div className="modal-actions">
              <button
                onClick={handleExecuteModule}
                disabled={executing !== null}
                className="btn btn-primary"
              >
                {executing === selectedModule.id ? '⏳ Executing...' : '🚀 Execute Module'}
              </button>
              <button
                onClick={() => setSelectedModule(null)}
                className="btn btn-secondary"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .module-selector {
          padding: 2rem;
        }
        
        .module-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 2rem;
        }
        
        .module-header h2 {
          font-size: 1.875rem;
          font-weight: 600;
          color: var(--text-primary);
          margin: 0;
        }
        
        .module-count {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }
        
        .module-filters {
          margin-bottom: 2rem;
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }
        
        .filter-group {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          flex-wrap: wrap;
        }
        
        .filter-label {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-primary);
        }
        
        .filter-buttons {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
        }
        
        .filter-btn {
          padding: 0.5rem 1rem;
          font-size: 0.875rem;
          border: 1px solid var(--border-color);
          background: var(--bg-secondary);
          color: var(--text-primary);
          border-radius: 0.375rem;
          cursor: pointer;
          transition: all 0.2s;
          text-transform: capitalize;
        }
        
        .filter-btn:hover {
          background: var(--bg-hover);
        }
        
        .filter-btn.active {
          background: var(--primary-color);
          color: white;
          border-color: var(--primary-color);
        }
        
        .search-input {
          width: 100%;
          padding: 0.75rem 1rem;
          border: 1px solid var(--border-color);
          border-radius: 0.5rem;
          font-size: 0.875rem;
          background: var(--bg-primary);
          color: var(--text-primary);
        }
        
        .search-input:focus {
          outline: none;
          border-color: var(--primary-color);
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .module-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
          gap: 1.5rem;
        }
        
        .module-card {
          border: 1px solid var(--border-color);
          border-radius: 0.75rem;
          padding: 1.5rem;
          cursor: pointer;
          transition: all 0.2s;
          background: var(--bg-secondary);
        }
        
        .module-card:hover {
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          transform: translateY(-2px);
          border-color: var(--primary-color);
        }
        
        .module-card-header {
          margin-bottom: 1rem;
        }
        
        .module-icon {
          font-size: 2.5rem;
        }
        
        .module-name {
          font-size: 1.125rem;
          font-weight: 600;
          color: var(--text-primary);
          margin: 0 0 0.5rem 0;
        }
        
        .module-description {
          font-size: 0.875rem;
          color: var(--text-secondary);
          margin: 0 0 1rem 0;
          line-height: 1.5;
        }
        
        .module-meta {
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        
        .module-category {
          padding: 0.25rem 0.75rem;
          background: var(--bg-hover);
          border-radius: 0.375rem;
          font-weight: 500;
        }
        
        .module-time {
          opacity: 0.8;
        }
        
        .empty-state {
          text-align: center;
          padding: 4rem 2rem;
          color: var(--text-secondary);
        }
        
        .empty-icon {
          font-size: 3rem;
          margin-bottom: 1rem;
        }
        
        .empty-title {
          font-size: 1.125rem;
          font-weight: 500;
          margin-bottom: 0.5rem;
        }
        
        .empty-subtitle {
          font-size: 0.875rem;
        }
        
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 1rem;
          z-index: 1000;
        }
        
        .modal-content {
          background: var(--bg-primary);
          border-radius: 0.75rem;
          max-width: 42rem;
          width: 100%;
          padding: 2rem;
          max-height: 90vh;
          overflow-y: auto;
        }
        
        .modal-header {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          margin-bottom: 1.5rem;
        }
        
        .modal-title-row {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-bottom: 0.5rem;
        }
        
        .modal-icon {
          font-size: 2rem;
        }
        
        .modal-header h3 {
          font-size: 1.5rem;
          font-weight: 600;
          color: var(--text-primary);
          margin: 0;
        }
        
        .modal-description {
          font-size: 0.875rem;
          color: var(--text-secondary);
          margin: 0;
        }
        
        .modal-close {
          background: none;
          border: none;
          font-size: 1.5rem;
          color: var(--text-secondary);
          cursor: pointer;
          padding: 0;
          line-height: 1;
        }
        
        .modal-close:hover {
          color: var(--text-primary);
        }
        
        .modal-meta {
          display: flex;
          align-items: center;
          gap: 1rem;
          margin-bottom: 1.5rem;
          font-size: 0.875rem;
          color: var(--text-secondary);
        }
        
        .meta-badge {
          padding: 0.25rem 0.75rem;
          background: var(--bg-hover);
          border-radius: 0.375rem;
          font-weight: 500;
        }
        
        .modal-params {
          margin-bottom: 1.5rem;
        }
        
        .modal-params h4 {
          font-size: 1rem;
          font-weight: 500;
          color: var(--text-primary);
          margin: 0 0 1rem 0;
        }
        
        .no-params {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }
        
        .params-list {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }
        
        .param-field label {
          display: block;
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-primary);
          margin-bottom: 0.5rem;
        }
        
        .param-field .required {
          color: var(--danger-color);
          margin-left: 0.25rem;
        }
        
        .param-description {
          font-size: 0.75rem;
          color: var(--text-secondary);
          margin: 0 0 0.5rem 0;
        }
        
        .param-input,
        .param-select {
          width: 100%;
          padding: 0.75rem;
          border: 1px solid var(--border-color);
          border-radius: 0.5rem;
          font-size: 0.875rem;
          background: var(--bg-secondary);
          color: var(--text-primary);
        }
        
        .param-input:focus,
        .param-select:focus {
          outline: none;
          border-color: var(--primary-color);
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .param-checkbox {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        
        .param-checkbox input {
          width: 1.25rem;
          height: 1.25rem;
          cursor: pointer;
        }
        
        .param-checkbox span {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }
        
        .modal-actions {
          display: flex;
          gap: 1rem;
        }
        
        .loading-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 4rem 2rem;
          color: var(--text-secondary);
        }
        
        .loading-spinner {
          width: 3rem;
          height: 3rem;
          border: 3px solid var(--border-color);
          border-top-color: var(--primary-color);
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin-bottom: 1rem;
        }
        
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
          .module-grid {
            grid-template-columns: 1fr;
          }
          
          .filter-group {
            flex-direction: column;
            align-items: flex-start;
          }
        }
      `}</style>
    </div>
  )
}
