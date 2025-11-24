/**
 * Findings Dashboard Component
 * 
 * Display security findings with:
 * - Findings table with severity color-coding
 * - Evidence viewer (requests, responses, screenshots)
 * - Export findings functionality
 * - Filter by severity and type
 */

import { useState, useEffect } from 'react'
import { getFindings } from '../services/api'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface Evidence {
  type: 'request' | 'response' | 'screenshot' | 'code'
  data: string
  description: string
  timestamp: string
}

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
  flags: string[]
  evidence: Evidence[]
  metadata?: Record<string, any>
}

interface FindingsDashboardProps {
  workspaceId?: string
  onFindingClick?: (finding: Finding) => void
  onExport?: (findings: Finding[]) => void
}

export default function FindingsDashboard({
  workspaceId,
  onFindingClick,
  onExport
}: FindingsDashboardProps) {
  const [findings, setFindings] = useState<Finding[]>([
    // Example finding
    {
      id: 'f1',
      title: 'SQL Injection in Login Form',
      vulnerabilityType: 'SQL Injection',
      severity: 'critical',
      affectedUrl: 'https://example.com/login',
      description: 'The login form is vulnerable to SQL injection via the username parameter.',
      proofOfConcept: "username: admin' OR '1'='1' --\npassword: anything",
      remediation: 'Use parameterized queries or prepared statements.',
      discoveredAt: new Date().toISOString(),
      flags: ['CTF{sql_injection_found}'],
      evidence: [
        {
          type: 'request',
          data: "POST /login HTTP/1.1\nHost: example.com\n\nusername=admin' OR '1'='1' --&password=test",
          description: 'Malicious request',
          timestamp: new Date().toISOString()
        },
        {
          type: 'response',
          data: 'HTTP/1.1 200 OK\n\nWelcome admin!',
          description: 'Successful bypass',
          timestamp: new Date().toISOString()
        }
      ]
    }
  ])
  
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(
    new Set(['critical', 'high', 'medium', 'low', 'info'])
  )
  const [searchQuery, setSearchQuery] = useState('')
  const [sortBy, setSortBy] = useState<'severity' | 'date'>('severity')
  
  // Get severity color
  const getSeverityColor = (severity: Severity): string => {
    switch (severity) {
      case 'critical': return 'text-red-700 bg-red-100 border-red-300'
      case 'high': return 'text-orange-700 bg-orange-100 border-orange-300'
      case 'medium': return 'text-yellow-700 bg-yellow-100 border-yellow-300'
      case 'low': return 'text-blue-700 bg-blue-100 border-blue-300'
      case 'info': return 'text-gray-700 bg-gray-100 border-gray-300'
    }
  }
  
  // Get severity badge color
  const getSeverityBadge = (severity: Severity): string => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white'
      case 'high': return 'bg-orange-600 text-white'
      case 'medium': return 'bg-yellow-600 text-white'
      case 'low': return 'bg-blue-600 text-white'
      case 'info': return 'bg-gray-600 text-white'
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
  
  // Sort findings
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    if (sortBy === 'severity') {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      return severityOrder[a.severity] - severityOrder[b.severity]
    } else {
      return new Date(b.discoveredAt).getTime() - new Date(a.discoveredAt).getTime()
    }
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
  const handleExport = (format: 'json' | 'markdown' | 'csv') => {
    if (format === 'json') {
      const dataStr = JSON.stringify(sortedFindings, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `findings-${Date.now()}.json`
      link.click()
    } else if (format === 'markdown') {
      let markdown = '# Security Findings Report\n\n'
      markdown += `Generated: ${new Date().toLocaleString()}\n\n`
      markdown += `Total Findings: ${sortedFindings.length}\n\n`
      
      sortedFindings.forEach((finding, i) => {
        markdown += `## ${i + 1}. ${finding.title}\n\n`
        markdown += `**Severity:** ${finding.severity.toUpperCase()}\n\n`
        markdown += `**Type:** ${finding.vulnerabilityType}\n\n`
        markdown += `**Affected URL:** ${finding.affectedUrl}\n\n`
        markdown += `**Description:**\n${finding.description}\n\n`
        markdown += `**Proof of Concept:**\n\`\`\`\n${finding.proofOfConcept}\n\`\`\`\n\n`
        markdown += `**Remediation:**\n${finding.remediation}\n\n`
        if (finding.flags.length > 0) {
          markdown += `**Flags:** ${finding.flags.join(', ')}\n\n`
        }
        markdown += '---\n\n'
      })
      
      const dataBlob = new Blob([markdown], { type: 'text/markdown' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `findings-${Date.now()}.md`
      link.click()
    } else if (format === 'csv') {
      const headers = ['Title', 'Severity', 'Type', 'URL', 'Discovered']
      const rows = sortedFindings.map(f => [
        f.title,
        f.severity,
        f.vulnerabilityType,
        f.affectedUrl,
        new Date(f.discoveredAt).toLocaleString()
      ])
      
      const csv = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
      ].join('\n')
      
      const dataBlob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `findings-${Date.now()}.csv`
      link.click()
    }
    
    onExport?.(sortedFindings)
  }
  
  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }
  
  return (
    <div className="findings-dashboard h-full flex flex-col">
      {/* Header */}
      <div className="border-b p-4 bg-white">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-semibold">Findings Dashboard</h2>
          <div className="flex gap-2">
            <button
              onClick={() => handleExport('json')}
              className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
            >
              Export JSON
            </button>
            <button
              onClick={() => handleExport('markdown')}
              className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
            >
              Export Markdown
            </button>
            <button
              onClick={() => handleExport('csv')}
              className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
            >
              Export CSV
            </button>
          </div>
        </div>
        
        {/* Stats */}
        <div className="grid grid-cols-5 gap-4 mb-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(severity => {
            const count = findings.filter(f => f.severity === severity).length
            return (
              <div key={severity} className={`p-3 border rounded-lg ${getSeverityColor(severity)}`}>
                <div className="text-2xl font-bold">{count}</div>
                <div className="text-sm capitalize">{severity}</div>
              </div>
            )
          })}
        </div>
        
        {/* Filters */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-700">Severity:</span>
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(severity => (
              <button
                key={severity}
                onClick={() => toggleSeverityFilter(severity)}
                className={`px-3 py-1 text-sm rounded capitalize ${
                  severityFilter.has(severity)
                    ? getSeverityBadge(severity)
                    : 'text-gray-400 bg-gray-100'
                }`}
              >
                {severity}
              </button>
            ))}
          </div>
          
          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search findings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 px-3 py-2 border rounded-lg"
            />
            
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="px-3 py-2 border rounded-lg"
            >
              <option value="severity">Sort by Severity</option>
              <option value="date">Sort by Date</option>
            </select>
            
            <div className="text-sm text-gray-600">
              {sortedFindings.length} of {findings.length} findings
            </div>
          </div>
        </div>
      </div>
      
      {/* Findings List */}
      <div className="flex-1 overflow-auto p-4">
        {sortedFindings.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <div className="text-4xl mb-2">🔍</div>
            <div>No findings to display</div>
            {findings.length > 0 && (
              <div className="text-sm mt-1">Try adjusting your filters</div>
            )}
          </div>
        ) : (
          <div className="space-y-4 max-w-6xl mx-auto">
            {sortedFindings.map((finding) => (
              <div
                key={finding.id}
                onClick={() => {
                  setSelectedFinding(finding)
                  onFindingClick?.(finding)
                }}
                className="border rounded-lg p-4 hover:shadow-md cursor-pointer transition-shadow"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className={`px-3 py-1 text-sm font-medium rounded uppercase ${getSeverityBadge(finding.severity)}`}>
                        {finding.severity}
                      </span>
                      <h3 className="text-lg font-semibold text-gray-900">{finding.title}</h3>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-gray-600">
                      <span className="font-medium">{finding.vulnerabilityType}</span>
                      <span>•</span>
                      <span className="font-mono text-xs">{finding.affectedUrl}</span>
                      <span>•</span>
                      <span>{new Date(finding.discoveredAt).toLocaleString()}</span>
                    </div>
                  </div>
                  
                  {finding.flags.length > 0 && (
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-green-700">🚩</span>
                      <span className="text-sm font-medium text-green-700">
                        {finding.flags.length} flag{finding.flags.length > 1 ? 's' : ''}
                      </span>
                    </div>
                  )}
                </div>
                
                <p className="text-sm text-gray-700 mb-3">{finding.description}</p>
                
                <div className="flex items-center gap-3 text-sm">
                  <span className="text-gray-600">
                    📎 {finding.evidence.length} evidence item{finding.evidence.length !== 1 ? 's' : ''}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedFinding(finding)
                    }}
                    className="text-blue-600 hover:text-blue-800"
                  >
                    View Details →
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedFinding(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-6xl w-full max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`px-3 py-1 text-sm font-medium rounded uppercase ${getSeverityBadge(selectedFinding.severity)}`}>
                      {selectedFinding.severity}
                    </span>
                    <h3 className="text-2xl font-semibold">{selectedFinding.title}</h3>
                  </div>
                  <div className="text-sm text-gray-600">
                    {selectedFinding.vulnerabilityType} • {new Date(selectedFinding.discoveredAt).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-6">
                {/* Affected URL */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Affected URL</div>
                  <div className="p-3 bg-gray-50 rounded font-mono text-sm">
                    {selectedFinding.affectedUrl}
                  </div>
                </div>
                
                {/* Description */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Description</div>
                  <div className="p-4 bg-gray-50 rounded text-sm">
                    {selectedFinding.description}
                  </div>
                </div>
                
                {/* Proof of Concept */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-sm font-medium text-gray-700">Proof of Concept</div>
                    <button
                      onClick={() => copyToClipboard(selectedFinding.proofOfConcept)}
                      className="text-sm text-blue-600 hover:text-blue-800"
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="p-4 bg-gray-900 text-green-400 rounded text-sm font-mono overflow-x-auto">
                    {selectedFinding.proofOfConcept}
                  </pre>
                </div>
                
                {/* Remediation */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Remediation</div>
                  <div className="p-4 bg-blue-50 border border-blue-200 rounded text-sm">
                    {selectedFinding.remediation}
                  </div>
                </div>
                
                {/* Flags */}
                {selectedFinding.flags.length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Captured Flags</div>
                    <div className="space-y-2">
                      {selectedFinding.flags.map((flag, i) => (
                        <div key={i} className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded">
                          <span className="flex-1 font-mono text-sm text-green-700">{flag}</span>
                          <button
                            onClick={() => copyToClipboard(flag)}
                            className="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700"
                          >
                            Copy
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Evidence */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Evidence ({selectedFinding.evidence.length})</div>
                  <div className="space-y-2">
                    {selectedFinding.evidence.map((evidence, i) => (
                      <div
                        key={i}
                        onClick={() => setSelectedEvidence(evidence)}
                        className="p-3 border rounded hover:bg-gray-50 cursor-pointer"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded uppercase">
                              {evidence.type}
                            </span>
                            <span className="text-sm">{evidence.description}</span>
                          </div>
                          <span className="text-xs text-gray-500">
                            {new Date(evidence.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Evidence Detail Modal */}
      {selectedEvidence && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedEvidence(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold">{selectedEvidence.description}</h3>
                  <div className="text-sm text-gray-600">
                    {selectedEvidence.type.toUpperCase()} • {new Date(selectedEvidence.timestamp).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvidence(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              <pre className="p-4 bg-gray-900 text-green-400 rounded text-sm font-mono overflow-x-auto max-h-96">
                {selectedEvidence.data}
              </pre>
              
              <div className="mt-4">
                <button
                  onClick={() => copyToClipboard(selectedEvidence.data)}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Copy to Clipboard
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
