/**
 * Workspace Manager Component
 * 
 * Multi-challenge organization with:
 * - Create/delete workspaces
 * - Switch between workspaces
 * - Export/import workspace archives
 * - Display workspace metadata
 */

import { useState, useEffect } from 'react'
import { getWorkspaces, createWorkspace, deleteWorkspace } from '../services/api'

interface Workspace {
  id: string
  name: string
  description: string
  createdAt: string
  updatedAt: string
  findingsCount: number
  targetUrl?: string
  metadata?: Record<string, any>
}

interface WorkspaceManagerProps {
  currentWorkspaceId?: string
  onWorkspaceChange?: (workspaceId: string) => void
  onWorkspaceCreate?: (workspace: Omit<Workspace, 'id' | 'createdAt' | 'updatedAt' | 'findingsCount'>) => void
  onWorkspaceDelete?: (workspaceId: string) => void
  onWorkspaceExport?: (workspaceId: string) => void
  onWorkspaceImport?: (file: File) => void
}

export default function WorkspaceManager({
  currentWorkspaceId,
  onWorkspaceChange,
  onWorkspaceCreate,
  onWorkspaceDelete,
  onWorkspaceExport,
  onWorkspaceImport
}: WorkspaceManagerProps) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  
  // Load workspaces from API
  useEffect(() => {
    loadWorkspaces()
  }, [])
  
  const loadWorkspaces = async () => {
    try {
      setLoading(true)
      const response = await getWorkspaces()
      // Map API response to component format
      const mappedWorkspaces = (response.data || []).map((ws: any) => ({
        id: ws.workspace_id,
        name: ws.name,
        description: ws.description,
        createdAt: ws.created_at,
        updatedAt: ws.updated_at,
        findingsCount: ws.findings_count,
        targetUrl: ws.target_url,
        metadata: ws.metadata
      }))
      setWorkspaces(mappedWorkspaces)
      setError('')
    } catch (err: any) {
      console.error('Failed to load workspaces:', err)
      setError(err.response?.data?.detail || 'Failed to load workspaces')
      // Set default workspace if API fails
      setWorkspaces([{
        id: 'ws-1',
        name: 'Default Workspace',
        description: 'Main workspace for testing',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        findingsCount: 0
      }])
    } finally {
      setLoading(false)
    }
  }
  
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [selectedWorkspace, setSelectedWorkspace] = useState<Workspace | null>(null)
  
  // Create form state
  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newTargetUrl, setNewTargetUrl] = useState('')
  
  // Import state
  const [importFile, setImportFile] = useState<File | null>(null)
  
  // Get current workspace
  const currentWorkspace = workspaces.find(w => w.id === currentWorkspaceId) || workspaces[0]
  
  // Create workspace
  const handleCreate = async () => {
    if (!newName.trim()) {
      alert('Workspace name is required')
      return
    }
    
    try {
      await createWorkspace({
        name: newName,
        description: newDescription,
        target_url: newTargetUrl || undefined
      })
      
      // Reload workspaces
      await loadWorkspaces()
      
      onWorkspaceCreate?.({
        name: newName,
        description: newDescription,
        targetUrl: newTargetUrl || undefined
      })
      
      // Reset form
      setNewName('')
      setNewDescription('')
      setNewTargetUrl('')
      setShowCreateModal(false)
      
      alert(`Workspace "${newName}" created successfully!`)
    } catch (err: any) {
      console.error('Failed to create workspace:', err)
      alert(err.response?.data?.detail || 'Failed to create workspace')
    }
  }
  
  // Delete workspace
  const handleDelete = async (workspace: Workspace) => {
    if (workspaces.length === 1) {
      alert('Cannot delete the last workspace')
      return
    }
    
    if (confirm(`Delete workspace "${workspace.name}"? This cannot be undone.`)) {
      try {
        await deleteWorkspace(workspace.id)
        
        // Reload workspaces
        await loadWorkspaces()
        
        onWorkspaceDelete?.(workspace.id)
        
        // Switch to another workspace if deleting current
        if (workspace.id === currentWorkspaceId) {
          const nextWorkspace = workspaces.find(w => w.id !== workspace.id)
          if (nextWorkspace) {
            onWorkspaceChange?.(nextWorkspace.id)
          }
        }
        
        alert(`Workspace "${workspace.name}" deleted successfully`)
      } catch (err: any) {
        console.error('Failed to delete workspace:', err)
        alert(err.response?.data?.detail || 'Failed to delete workspace')
      }
    }
  }
  
  // Export workspace
  const handleExport = (workspace: Workspace) => {
    onWorkspaceExport?.(workspace.id)
    
    // Create download
    const data = {
      workspace,
      exportedAt: new Date().toISOString(),
      version: '1.0.0'
    }
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `workspace-${workspace.name.replace(/\s+/g, '-')}-${Date.now()}.json`
    link.click()
    URL.revokeObjectURL(url)
  }
  
  // Import workspace
  const handleImport = () => {
    if (!importFile) {
      alert('Please select a file to import')
      return
    }
    
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string)
        
        if (!data.workspace) {
          throw new Error('Invalid workspace file')
        }
        
        const importedWorkspace: Workspace = {
          ...data.workspace,
          id: `ws-${Date.now()}`,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        }
        
        setWorkspaces([...workspaces, importedWorkspace])
        onWorkspaceImport?.(importFile)
        
        setImportFile(null)
        setShowImportModal(false)
        
        alert(`Workspace "${importedWorkspace.name}" imported successfully`)
      } catch (error) {
        alert('Failed to import workspace: Invalid file format')
      }
    }
    
    reader.readAsText(importFile)
  }
  
  // Switch workspace
  const handleSwitch = (workspaceId: string) => {
    onWorkspaceChange?.(workspaceId)
  }
  
  if (loading) {
    return (
      <div className="workspace-manager p-6 bg-white rounded-lg shadow">
        <div className="flex items-center justify-center py-12">
          <div className="spinner"></div>
        </div>
      </div>
    )
  }
  
  return (
    <div className="workspace-manager p-6 bg-white rounded-lg shadow">
      {error && (
        <div className="alert error mb-4">
          <strong>Error:</strong> {error}
        </div>
      )}
      
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-semibold">Workspace Manager</h2>
        <div className="flex gap-2">
          <button
            onClick={() => setShowImportModal(true)}
            className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
          >
            📥 Import
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            ➕ New Workspace
          </button>
        </div>
      </div>
      
      {/* Current Workspace Info */}
      <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-sm font-medium text-blue-900">Current Workspace:</span>
              <span className="text-lg font-semibold text-blue-700">{currentWorkspace.name}</span>
            </div>
            {currentWorkspace.description && (
              <p className="text-sm text-blue-700 mb-2">{currentWorkspace.description}</p>
            )}
            <div className="flex items-center gap-4 text-sm text-blue-600">
              <span>Findings: {currentWorkspace.findingsCount}</span>
              <span>•</span>
              <span>Updated: {new Date(currentWorkspace.updatedAt).toLocaleDateString()}</span>
              {currentWorkspace.targetUrl && (
                <>
                  <span>•</span>
                  <span className="font-mono">{currentWorkspace.targetUrl}</span>
                </>
              )}
            </div>
          </div>
          <button
            onClick={() => handleExport(currentWorkspace)}
            className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            📤 Export
          </button>
        </div>
      </div>
      
      {/* Workspace List */}
      <div className="space-y-3">
        <h3 className="text-lg font-medium text-gray-900">All Workspaces</h3>
        
        {workspaces.map((workspace) => (
          <div
            key={workspace.id}
            className={`p-4 border rounded-lg ${
              workspace.id === currentWorkspaceId
                ? 'border-blue-500 bg-blue-50'
                : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <h4 className="font-semibold text-gray-900">{workspace.name}</h4>
                  {workspace.id === currentWorkspaceId && (
                    <span className="px-2 py-0.5 text-xs bg-blue-600 text-white rounded">
                      Active
                    </span>
                  )}
                </div>
                
                {workspace.description && (
                  <p className="text-sm text-gray-600 mb-2">{workspace.description}</p>
                )}
                
                <div className="flex items-center gap-4 text-sm text-gray-500">
                  <span>🔍 {workspace.findingsCount} findings</span>
                  <span>📅 {new Date(workspace.createdAt).toLocaleDateString()}</span>
                  {workspace.targetUrl && (
                    <span className="font-mono text-xs">{workspace.targetUrl}</span>
                  )}
                </div>
              </div>
              
              <div className="flex gap-2">
                {workspace.id !== currentWorkspaceId && (
                  <button
                    onClick={() => handleSwitch(workspace.id)}
                    className="px-3 py-1 text-sm bg-gray-100 text-gray-700 rounded hover:bg-gray-200"
                  >
                    Switch
                  </button>
                )}
                <button
                  onClick={() => setSelectedWorkspace(workspace)}
                  className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
                >
                  Details
                </button>
                <button
                  onClick={() => handleExport(workspace)}
                  className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
                >
                  Export
                </button>
                <button
                  onClick={() => handleDelete(workspace)}
                  className="px-3 py-1 text-sm text-red-600 hover:text-red-800"
                  disabled={workspaces.length === 1}
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {/* Create Modal */}
      {showCreateModal && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setShowCreateModal(false)}
        >
          <div 
            className="bg-white rounded-lg max-w-2xl w-full p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-semibold mb-4">Create New Workspace</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Workspace Name *
                </label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="My CTF Challenge"
                  className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  autoFocus
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Description
                </label>
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Optional description of this workspace"
                  rows={3}
                  className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Target URL
                </label>
                <input
                  type="url"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={handleCreate}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Create Workspace
              </button>
              <button
                onClick={() => setShowCreateModal(false)}
                className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Import Modal */}
      {showImportModal && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setShowImportModal(false)}
        >
          <div 
            className="bg-white rounded-lg max-w-2xl w-full p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-xl font-semibold mb-4">Import Workspace</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Select Workspace File
                </label>
                <input
                  type="file"
                  accept=".json,.tar.gz"
                  onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                  className="w-full px-3 py-2 border rounded-lg"
                />
                <p className="mt-2 text-sm text-gray-500">
                  Supported formats: JSON (.json), Archive (.tar.gz)
                </p>
              </div>
              
              {importFile && (
                <div className="p-3 bg-gray-50 rounded">
                  <div className="text-sm font-medium text-gray-700">Selected File:</div>
                  <div className="text-sm text-gray-600">{importFile.name}</div>
                  <div className="text-xs text-gray-500">
                    {(importFile.size / 1024).toFixed(2)} KB
                  </div>
                </div>
              )}
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={handleImport}
                disabled={!importFile}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Import Workspace
              </button>
              <button
                onClick={() => {
                  setShowImportModal(false)
                  setImportFile(null)
                }}
                className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Details Modal */}
      {selectedWorkspace && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedWorkspace(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-2xl w-full p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold">Workspace Details</h3>
              <button
                onClick={() => setSelectedWorkspace(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                ✕
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-600">Name</div>
                  <div className="font-medium">{selectedWorkspace.name}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">ID</div>
                  <div className="font-mono text-sm">{selectedWorkspace.id}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Created</div>
                  <div className="font-medium">
                    {new Date(selectedWorkspace.createdAt).toLocaleString()}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Last Updated</div>
                  <div className="font-medium">
                    {new Date(selectedWorkspace.updatedAt).toLocaleString()}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-600">Findings</div>
                  <div className="font-medium">{selectedWorkspace.findingsCount}</div>
                </div>
                {selectedWorkspace.targetUrl && (
                  <div>
                    <div className="text-sm text-gray-600">Target URL</div>
                    <div className="font-mono text-sm">{selectedWorkspace.targetUrl}</div>
                  </div>
                )}
              </div>
              
              {selectedWorkspace.description && (
                <div>
                  <div className="text-sm text-gray-600 mb-1">Description</div>
                  <div className="p-3 bg-gray-50 rounded">{selectedWorkspace.description}</div>
                </div>
              )}
              
              {selectedWorkspace.metadata && Object.keys(selectedWorkspace.metadata).length > 0 && (
                <div>
                  <div className="text-sm text-gray-600 mb-1">Metadata</div>
                  <pre className="p-3 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                    {JSON.stringify(selectedWorkspace.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
