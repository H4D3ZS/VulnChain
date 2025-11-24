/**
 * Fuzzing Monitor Component
 * 
 * Real-time display of fuzzing results with:
 * - WebSocket connection for live updates
 * - Smart filtering by response length and status
 * - Color-coded entries by status and anomalies
 * - Detailed request/response viewer
 * - Pagination and search
 */

import { useState, useEffect, useCallback, useMemo } from 'react'

interface FuzzingResult {
  id: string
  payload: string
  status: number
  length: number
  time: number
  timestamp: string
  request?: {
    method: string
    url: string
    headers: Record<string, string>
    body?: string
  }
  response?: {
    headers: Record<string, string>
    body: string
  }
  isAnomaly?: boolean
}

interface FuzzingMonitorProps {
  websocketUrl?: string
  onResultClick?: (result: FuzzingResult) => void
}

export default function FuzzingMonitor({ 
  websocketUrl = 'ws://localhost:8000/ws/fuzzing',
  onResultClick 
}: FuzzingMonitorProps) {
  const [results, setResults] = useState<FuzzingResult[]>([])
  const [selectedResult, setSelectedResult] = useState<FuzzingResult | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [ws, setWs] = useState<WebSocket | null>(null)
  
  // Filter state
  const [statusFilter, setStatusFilter] = useState<Set<number>>(new Set([200, 301, 302, 400, 401, 403, 404, 500]))
  const [lengthThreshold, setLengthThreshold] = useState<number>(10)
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [showAnomaliesOnly, setShowAnomaliesOnly] = useState<boolean>(false)
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState<number>(1)
  const [pageSize, setPageSize] = useState<number>(50)
  
  // Connect to WebSocket
  useEffect(() => {
    const websocket = new WebSocket(websocketUrl)
    
    websocket.onopen = () => {
      console.log('[FuzzingMonitor] WebSocket connected')
      setIsConnected(true)
    }
    
    websocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        
        if (data.type === 'fuzzing_result') {
          const result: FuzzingResult = {
            id: data.id || `${Date.now()}-${Math.random()}`,
            payload: data.payload,
            status: data.status,
            length: data.length,
            time: data.time,
            timestamp: data.timestamp || new Date().toISOString(),
            request: data.request,
            response: data.response,
            isAnomaly: data.isAnomaly || false
          }
          
          setResults(prev => [result, ...prev])
        }
      } catch (error) {
        console.error('[FuzzingMonitor] Error parsing message:', error)
      }
    }
    
    websocket.onerror = (error) => {
      console.error('[FuzzingMonitor] WebSocket error:', error)
    }
    
    websocket.onclose = () => {
      console.log('[FuzzingMonitor] WebSocket disconnected')
      setIsConnected(false)
    }
    
    setWs(websocket)
    
    return () => {
      websocket.close()
    }
  }, [websocketUrl])
  
  // Calculate baseline for anomaly detection
  const baseline = useMemo(() => {
    if (results.length < 10) return null
    
    const lengths = results.slice(0, 100).map(r => r.length)
    const sum = lengths.reduce((a, b) => a + b, 0)
    const avg = sum / lengths.length
    
    return avg
  }, [results])
  
  // Filter results
  const filteredResults = useMemo(() => {
    let filtered = results
    
    // Status filter
    if (statusFilter.size > 0) {
      filtered = filtered.filter(r => statusFilter.has(r.status))
    }
    
    // Length threshold filter (percentage difference from baseline)
    if (baseline && lengthThreshold > 0) {
      filtered = filtered.filter(r => {
        const diff = Math.abs(r.length - baseline) / baseline * 100
        return diff >= lengthThreshold
      })
    }
    
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(r => 
        r.payload.toLowerCase().includes(query) ||
        r.status.toString().includes(query)
      )
    }
    
    // Anomaly filter
    if (showAnomaliesOnly) {
      filtered = filtered.filter(r => r.isAnomaly)
    }
    
    return filtered
  }, [results, statusFilter, lengthThreshold, baseline, searchQuery, showAnomaliesOnly])
  
  // Paginate results
  const paginatedResults = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    const end = start + pageSize
    return filteredResults.slice(start, end)
  }, [filteredResults, currentPage, pageSize])
  
  const totalPages = Math.ceil(filteredResults.length / pageSize)
  
  // Get status color
  const getStatusColor = (status: number): string => {
    if (status >= 200 && status < 300) return 'text-green-600 bg-green-50'
    if (status >= 300 && status < 400) return 'text-yellow-600 bg-yellow-50'
    if (status >= 400 && status < 500) return 'text-orange-600 bg-orange-50'
    if (status >= 500) return 'text-red-600 bg-red-50'
    return 'text-gray-600 bg-gray-50'
  }
  
  // Handle result click
  const handleResultClick = (result: FuzzingResult) => {
    setSelectedResult(result)
    onResultClick?.(result)
  }
  
  // Toggle status filter
  const toggleStatusFilter = (status: number) => {
    setStatusFilter(prev => {
      const newSet = new Set(prev)
      if (newSet.has(status)) {
        newSet.delete(status)
      } else {
        newSet.add(status)
      }
      return newSet
    })
  }
  
  // Clear filters
  const clearFilters = () => {
    setStatusFilter(new Set([200, 301, 302, 400, 401, 403, 404, 500]))
    setLengthThreshold(10)
    setSearchQuery('')
    setShowAnomaliesOnly(false)
  }
  
  return (
    <div className="fuzzing-monitor h-full flex flex-col">
      {/* Header */}
      <div className="border-b p-4 bg-white">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-semibold">Fuzzing Monitor</h2>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-600">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
          
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span>Total: {results.length}</span>
            <span>•</span>
            <span>Filtered: {filteredResults.length}</span>
            {baseline && (
              <>
                <span>•</span>
                <span>Baseline: {baseline.toFixed(0)} bytes</span>
              </>
            )}
          </div>
        </div>
        
        {/* Filters */}
        <div className="space-y-3">
          {/* Status filter */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-700">Status:</span>
            {[200, 301, 302, 400, 401, 403, 404, 500].map(status => (
              <button
                key={status}
                onClick={() => toggleStatusFilter(status)}
                className={`px-3 py-1 text-sm rounded ${
                  statusFilter.has(status)
                    ? getStatusColor(status)
                    : 'text-gray-400 bg-gray-100'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
          
          {/* Length threshold and search */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <label className="text-sm font-medium text-gray-700">
                Length Diff %:
              </label>
              <input
                type="number"
                value={lengthThreshold}
                onChange={(e) => setLengthThreshold(Number(e.target.value))}
                className="w-20 px-2 py-1 text-sm border rounded"
                min="0"
                max="100"
              />
            </div>
            
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="anomalies"
                checked={showAnomaliesOnly}
                onChange={(e) => setShowAnomaliesOnly(e.target.checked)}
                className="rounded"
              />
              <label htmlFor="anomalies" className="text-sm font-medium text-gray-700">
                Anomalies Only
              </label>
            </div>
            
            <input
              type="text"
              placeholder="Search payloads..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 px-3 py-1 text-sm border rounded"
            />
            
            <button
              onClick={clearFilters}
              className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>
      
      {/* Results Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 sticky top-0">
            <tr>
              <th className="px-4 py-2 text-left font-medium text-gray-700">Payload</th>
              <th className="px-4 py-2 text-left font-medium text-gray-700">Status</th>
              <th className="px-4 py-2 text-left font-medium text-gray-700">Length</th>
              <th className="px-4 py-2 text-left font-medium text-gray-700">Time (ms)</th>
              <th className="px-4 py-2 text-left font-medium text-gray-700">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {paginatedResults.map((result) => (
              <tr
                key={result.id}
                onClick={() => handleResultClick(result)}
                className={`border-b cursor-pointer hover:bg-gray-50 ${
                  result.isAnomaly ? 'bg-yellow-50' : ''
                }`}
              >
                <td className="px-4 py-2 font-mono text-xs max-w-md truncate">
                  {result.payload}
                </td>
                <td className="px-4 py-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(result.status)}`}>
                    {result.status}
                  </span>
                </td>
                <td className="px-4 py-2 text-gray-600">
                  {result.length.toLocaleString()}
                  {baseline && (
                    <span className="ml-1 text-xs text-gray-400">
                      ({((result.length - baseline) / baseline * 100).toFixed(1)}%)
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 text-gray-600">{result.time.toFixed(2)}</td>
                <td className="px-4 py-2 text-gray-500 text-xs">
                  {new Date(result.timestamp).toLocaleTimeString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        
        {paginatedResults.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            {results.length === 0 ? 'No fuzzing results yet' : 'No results match the current filters'}
          </div>
        )}
      </div>
      
      {/* Pagination */}
      {totalPages > 1 && (
        <div className="border-t p-4 bg-white flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-600">Page size:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value))
                setCurrentPage(1)
              }}
              className="px-2 py-1 text-sm border rounded"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="200">200</option>
            </select>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="text-sm text-gray-600">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1 text-sm border rounded disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}
      
      {/* Detail Modal */}
      {selectedResult && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedResult(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Result Details</h3>
                <button
                  onClick={() => setSelectedResult(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                {/* Summary */}
                <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded">
                  <div>
                    <div className="text-sm text-gray-600">Status</div>
                    <div className={`font-medium ${getStatusColor(selectedResult.status)}`}>
                      {selectedResult.status}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Length</div>
                    <div className="font-medium">{selectedResult.length.toLocaleString()} bytes</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Time</div>
                    <div className="font-medium">{selectedResult.time.toFixed(2)} ms</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Timestamp</div>
                    <div className="font-medium">{new Date(selectedResult.timestamp).toLocaleString()}</div>
                  </div>
                </div>
                
                {/* Payload */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Payload</div>
                  <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                    {selectedResult.payload}
                  </pre>
                </div>
                
                {/* Request */}
                {selectedResult.request && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Request</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                      {selectedResult.request.method} {selectedResult.request.url}{'\n'}
                      {Object.entries(selectedResult.request.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                      {selectedResult.request.body && `\n\n${selectedResult.request.body}`}
                    </pre>
                  </div>
                )}
                
                {/* Response */}
                {selectedResult.response && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Response</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto max-h-96">
                      {Object.entries(selectedResult.response.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                      {'\n\n'}
                      {selectedResult.response.body}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
