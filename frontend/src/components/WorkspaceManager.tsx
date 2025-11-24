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

export default function WorkspaceManager() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [selectedWorkspace, setSelectedWorkspace] = useState<Workspace | null>(null)

  // Create form state
  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newTargetUrl, setNewTargetUrl] = useState('')

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
        findingsCount: ws.findings_count || 0,
        targetUrl: ws.target_url,
        metadata: ws.metadata
      }))
      setWorkspaces(mappedWorkspaces)
      setError('')
    } catch (err: any) {
      console.error('Failed to load workspaces:', err)
      setError(err.response?.data?.detail || 'Failed to load workspaces')
    } finally {
      setLoading(false)
    }
  }

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

      await loadWorkspaces()

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

  const handleDelete = async (workspace: Workspace) => {
    if (workspaces.length === 1) {
      alert('Cannot delete the last workspace')
      return
    }

    if (confirm(`Delete workspace "${workspace.name}"? This cannot be undone.`)) {
      try {
        await deleteWorkspace(workspace.id)
        await loadWorkspaces()
        alert(`Workspace "${workspace.name}" deleted successfully`)
      } catch (err: any) {
        console.error('Failed to delete workspace:', err)
        alert(err.response?.data?.detail || 'Failed to delete workspace')
      }
    }
  }

  const handleExport = (workspace: Workspace) => {
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

  if (loading) {
    return (
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem' }}>
          <div className="spinner"></div>
        </div>
      </div>
    )
  }

  return (
    <div>
      {error && (
        <div className="alert error">
          <strong>Error:</strong> {error}
        </div>
      )}

      <div className="card">
        <div className="flex-between" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <h2>Workspace Manager</h2>
          <button onClick={() => setShowCreateModal(true)}>
            ➕ New Workspace
          </button>
        </div>

        {workspaces.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 'var(--spacing-xl)', color: 'var(--text-secondary)' }}>
            <p>No workspaces found. Create your first workspace to get started!</p>
            <button onClick={() => setShowCreateModal(true)} style={{ marginTop: 'var(--spacing-md)' }}>
              Create Workspace
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Findings</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {workspaces.map((workspace) => (
                  <tr key={workspace.id}>
                    <td>
                      <strong>{workspace.name}</strong>
                      {workspace.targetUrl && (
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)', marginTop: '0.25rem' }}>
                          {workspace.targetUrl}
                        </div>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>
                      {workspace.description || '-'}
                    </td>
                    <td>
                      <span className="badge info">{workspace.findingsCount}</span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 'var(--font-size-sm)' }}>
                      {new Date(workspace.createdAt).toLocaleDateString()}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 'var(--spacing-xs)' }}>
                        <button
                          className="secondary"
                          onClick={() => setSelectedWorkspace(workspace)}
                          style={{ padding: 'var(--spacing-xs) var(--spacing-sm)', fontSize: 'var(--font-size-sm)' }}
                        >
                          View
                        </button>
                        <button
                          className="secondary"
                          onClick={() => handleExport(workspace)}
                          style={{ padding: 'var(--spacing-xs) var(--spacing-sm)', fontSize: 'var(--font-size-sm)' }}
                        >
                          Export
                        </button>
                        <button
                          className="danger"
                          onClick={() => handleDelete(workspace)}
                          disabled={workspaces.length === 1}
                          style={{ padding: 'var(--spacing-xs) var(--spacing-sm)', fontSize: 'var(--font-size-sm)' }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--spacing-md)',
            zIndex: 1000
          }}
          onClick={() => setShowCreateModal(false)}
        >
          <div
            className="card"
            style={{ maxWidth: '600px', width: '100%', margin: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ marginBottom: 'var(--spacing-lg)' }}>Create New Workspace</h3>

            <div>
              <label>Workspace Name *</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="My CTF Challenge"
                autoFocus
              />
            </div>

            <div>
              <label>Description</label>
              <textarea
                value={newDescription}
                onChange={(e) => setNewDescription(e.target.value)}
                placeholder="Optional description of this workspace"
                rows={3}
              />
            </div>

            <div>
              <label>Target URL</label>
              <input
                type="url"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                placeholder="https://example.com"
              />
            </div>

            <div style={{ display: 'flex', gap: 'var(--spacing-sm)', marginTop: 'var(--spacing-lg)' }}>
              <button onClick={handleCreate}>
                Create Workspace
              </button>
              <button className="secondary" onClick={() => setShowCreateModal(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Details Modal */}
      {selectedWorkspace && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--spacing-md)',
            zIndex: 1000
          }}
          onClick={() => setSelectedWorkspace(null)}
        >
          <div
            className="card"
            style={{ maxWidth: '600px', width: '100%', margin: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex-between" style={{ marginBottom: 'var(--spacing-lg)' }}>
              <h3>Workspace Details</h3>
              <button
                className="secondary"
                onClick={() => setSelectedWorkspace(null)}
                style={{ padding: 'var(--spacing-xs) var(--spacing-sm)' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 'var(--spacing-md)' }}>
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Name
                </div>
                <div><strong>{selectedWorkspace.name}</strong></div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  ID
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 'var(--font-size-sm)' }}>
                  {selectedWorkspace.id}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Created
                </div>
                <div>{new Date(selectedWorkspace.createdAt).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Last Updated
                </div>
                <div>{new Date(selectedWorkspace.updatedAt).toLocaleString()}</div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Findings
                </div>
                <div><strong>{selectedWorkspace.findingsCount}</strong></div>
              </div>
              {selectedWorkspace.targetUrl && (
                <div style={{ gridColumn: '1 / -1' }}>
                  <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                    Target URL
                  </div>
                  <div style={{ fontFamily: 'monospace', fontSize: 'var(--font-size-sm)' }}>
                    {selectedWorkspace.targetUrl}
                  </div>
                </div>
              )}
            </div>

            {selectedWorkspace.description && (
              <div style={{ marginTop: 'var(--spacing-md)' }}>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Description
                </div>
                <div style={{ padding: 'var(--spacing-sm)', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px' }}>
                  {selectedWorkspace.description}
                </div>
              </div>
            )}

            {selectedWorkspace.metadata && Object.keys(selectedWorkspace.metadata).length > 0 && (
              <div style={{ marginTop: 'var(--spacing-md)' }}>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--spacing-xs)' }}>
                  Metadata
                </div>
                <pre style={{
                  padding: 'var(--spacing-sm)',
                  backgroundColor: 'var(--bg-tertiary)',
                  borderRadius: '6px',
                  fontSize: 'var(--font-size-xs)',
                  fontFamily: 'monospace',
                  overflowX: 'auto'
                }}>
                  {JSON.stringify(selectedWorkspace.metadata, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
