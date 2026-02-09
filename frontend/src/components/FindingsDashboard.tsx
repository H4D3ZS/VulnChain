import { useState, useEffect } from 'react'
import { getFindings } from '../services/api'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface Finding {
  id: string
  title: string
  vulnerabilityType: string
  severity: Severity
  affectedUrl: string
  description: string
  proofOfConcept: string
  remediation: string
  discoveredAt: string
  confidence?: number
  parameter?: string
  payload?: string
  evidence?: string[]
}

export default function FindingsDashboard() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(
    new Set(['critical', 'high', 'medium', 'low', 'info'])
  )
  const [searchQuery, setSearchQuery] = useState('')

  // Load findings from API
  useEffect(() => {
    loadFindings()
    // Refresh every 5 seconds
    const interval = setInterval(loadFindings, 5000)
    return () => clearInterval(interval)
  }, [])

  const loadFindings = async () => {
    try {
      setLoading(true)
      const response = await getFindings()
      setFindings(response.data || [])
      setError('')
    } catch (err: any) {
      console.error('Failed to load findings:', err)
      setError(err.response?.data?.detail || 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }

  // Filter findings
  const filteredFindings = findings.filter(finding => {
    if (!severityFilter.has(finding.severity)) return false

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        finding.title.toLowerCase().includes(query) ||
        finding.vulnerabilityType.toLowerCase().includes(query) ||
        finding.affectedUrl.toLowerCase().includes(query)
      )
    }

    return true
  })

  // Sort by severity
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })

  // Toggle severity filter
  const toggleSeverityFilter = (severity: Severity) => {
    setSeverityFilter(prev => {
      const newSet = new Set(prev)
      if (newSet.has(severity)) {
        newSet.delete(severity)
      } else {
        newSet.add(severity)
      }
      return newSet
    })
  }

  // Export findings
  const handleExport = (format: 'json' | 'markdown') => {
    if (format === 'json') {
      const dataStr = JSON.stringify(sortedFindings, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `findings-${Date.now()}.json`
      link.click()
      URL.revokeObjectURL(url)
    } else if (format === 'markdown') {
      let markdown = '# Security Findings Report\\n\\n'
      markdown += `Generated: ${new Date().toLocaleString()}\\n\\n`
      markdown += `Total Findings: ${sortedFindings.length}\\n\\n`

      sortedFindings.forEach((finding, i) => {
        markdown += `## ${i + 1}. ${finding.title}\\n\\n`
        markdown += `**Severity:** ${finding.severity.toUpperCase()}\\n\\n`
        markdown += `**Type:** ${finding.vulnerabilityType}\\n\\n`
        markdown += `**URL:** ${finding.affectedUrl}\\n\\n`
        markdown += `**Description:** ${finding.description}\\n\\n`
        if (finding.proofOfConcept) {
          markdown += `**Proof of Concept:**\\n\`\`\`\\n${finding.proofOfConcept}\\n\`\`\`\\n\\n`
        }
        markdown += '---\\n\\n'
      })

      const dataBlob = new Blob([markdown], { type: 'text/markdown' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `findings-${Date.now()}.md`
      link.click()
      URL.revokeObjectURL(url)
    }
  }

  if (loading && findings.length === 0) {
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
        <div className="alert error" style={{ marginBottom: 'var(--spacing-md)' }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      <div className="card">
        <div className="flex-between" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <h2>Findings Dashboard</h2>
          <div style={{ display: 'flex', gap: 'var(--spacing-xs)' }}>
            <button className="secondary" onClick={() => handleExport('json')}>
              Export JSON
            </button>
            <button className="secondary" onClick={() => handleExport('markdown')}>
              Export Markdown
            </button>
            <button onClick={loadFindings}>
              🔄 Refresh
            </button>
          </div>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 'var(--spacing-md)', marginBottom: 'var(--spacing-lg)' }}>
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(severity => {
            const count = findings.filter(f => f.severity === severity).length
            return (
              <div key={severity} className="card" style={{ textAlign: 'center', padding: 'var(--spacing-md)' }}>
                <div style={{ fontSize: '2rem', fontWeight: 'bold' }}>{count}</div>
                <div style={{ fontSize: 'var(--font-size-sm)', textTransform: 'capitalize', color: 'var(--text-secondary)' }}>
                  {severity}
                </div>
              </div>
            )
          })}
        </div>

        {/* Filters */}
        <div style={{ marginBottom: 'var(--spacing-lg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)', marginBottom: 'var(--spacing-md)', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600 }}>Severity:</span>
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(severity => (
              <button
                key={severity}
                onClick={() => toggleSeverityFilter(severity)}
                className={severityFilter.has(severity) ? '' : 'secondary'}
                style={{
                  padding: 'var(--spacing-xs) var(--spacing-sm)',
                  fontSize: 'var(--font-size-sm)',
                  textTransform: 'capitalize',
                  opacity: severityFilter.has(severity) ? 1 : 0.5
                }}
              >
                {severity}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 'var(--spacing-sm)', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search findings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ flex: 1 }}
            />
            <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
              {sortedFindings.length} of {findings.length} findings
            </span>
          </div>
        </div>

        {/* Findings List */}
        {sortedFindings.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 'var(--spacing-xl)', color: 'var(--text-secondary)' }}>
            <div style={{ fontSize: '3rem', marginBottom: 'var(--spacing-sm)' }}>🔍</div>
            <div>No findings to display</div>
            {findings.length > 0 && (
              <div style={{ fontSize: 'var(--font-size-sm)', marginTop: 'var(--spacing-xs)' }}>
                Try adjusting your filters
              </div>
            )}
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Type</th>
                  <th>URL</th>
                  <th>Discovered</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedFindings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <span className={`badge ${finding.severity}`} style={{ textTransform: 'uppercase' }}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      <strong>{finding.title}</strong>
                      {finding.confidence && (
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--text-tertiary)' }}>
                          Confidence: {(finding.confidence * 100).toFixed(0)}%
                        </div>
                      )}
                    </td>
                    <td>{finding.vulnerabilityType}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 'var(--font-size-xs)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {finding.affectedUrl}
                    </td>
                    <td style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                      {new Date(finding.discoveredAt).toLocaleString()}
                    </td>
                    <td>
                      <button
                        className="secondary"
                        onClick={() => setSelectedFinding(finding)}
                        style={{ padding: 'var(--spacing-xs) var(--spacing-sm)', fontSize: 'var(--font-size-sm)' }}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
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
          onClick={() => setSelectedFinding(null)}
        >
          <div
            className="card"
            style={{ maxWidth: '800px', width: '100%', maxHeight: '90vh', overflow: 'auto', margin: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex-between" style={{ marginBottom: 'var(--spacing-lg)' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-sm)', marginBottom: 'var(--spacing-xs)' }}>
                  <span className={`badge ${selectedFinding.severity}`} style={{ textTransform: 'uppercase' }}>
                    {selectedFinding.severity}
                  </span>
                  <h3>{selectedFinding.title}</h3>
                </div>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                  {selectedFinding.vulnerabilityType} • {new Date(selectedFinding.discoveredAt).toLocaleString()}
                </div>
              </div>
              <button
                className="secondary"
                onClick={() => setSelectedFinding(null)}
                style={{ padding: 'var(--spacing-xs) var(--spacing-sm)' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gap: 'var(--spacing-md)' }}>
              {/* Affected URL */}
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, marginBottom: 'var(--spacing-xs)' }}>
                  Affected URL
                </div>
                <div style={{ padding: 'var(--spacing-sm)', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px', fontFamily: 'monospace', fontSize: 'var(--font-size-sm)', wordBreak: 'break-all' }}>
                  {selectedFinding.affectedUrl}
                </div>
              </div>

              {/* Description */}
              <div>
                <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, marginBottom: 'var(--spacing-xs)' }}>
                  Description
                </div>
                <div style={{ padding: 'var(--spacing-sm)', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px' }}>
                  {selectedFinding.description}
                </div>
              </div>

              {/* Payload */}
              {selectedFinding.payload && (
                <div>
                  <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, marginBottom: 'var(--spacing-xs)' }}>
                    Payload
                  </div>
                  <div style={{ padding: 'var(--spacing-sm)', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px', fontFamily: 'monospace', fontSize: 'var(--font-size-sm)' }}>
                    {selectedFinding.payload}
                  </div>
                </div>
              )}

              {/* Evidence */}
              {selectedFinding.evidence && selectedFinding.evidence.length > 0 && (
                <div>
                  <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, marginBottom: 'var(--spacing-xs)' }}>
                    Evidence ({selectedFinding.evidence.length})
                  </div>
                  <div style={{ display: 'grid', gap: 'var(--spacing-xs)' }}>
                    {selectedFinding.evidence.map((item, i) => (
                      <div key={i} style={{ padding: 'var(--spacing-sm)', backgroundColor: 'var(--bg-tertiary)', borderRadius: '6px', fontSize: 'var(--font-size-sm)' }}>
                        {item}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation */}
              {selectedFinding.remediation && (
                <div>
                  <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, marginBottom: 'var(--spacing-xs)' }}>
                    Remediation
                  </div>
                  <div className="alert info">
                    {selectedFinding.remediation}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
