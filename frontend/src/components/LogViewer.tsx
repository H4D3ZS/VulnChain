/**
 * Log Viewer Component
 * 
 * Real-time log display with:
 * - WebSocket connection for live streaming
 * - Filter by level, module, time range
 * - Search functionality
 * - Color-coding by severity
 * - Export to JSON/CSV
 */

import { useState, useEffect, useRef } from 'react'

type LogLevel = 'debug' | 'info' | 'warning' | 'error' | 'critical'

interface LogEntry {
  id: string
  timestamp: string
  level: LogLevel
  module: string
  message: string
  metadata?: Record<string, any>
  request?: {
    method: string
    url: string
    headers?: Record<string, string>
  }
  response?: {
    status: number
    length: number
    time: number
  }
}

interface LogViewerProps {
  websocketUrl?: string
  maxLogs?: number
}

export default function LogViewer({ 
  websocketUrl = 'ws://localhost:8000/ws/logs',
  maxLogs = 1000
}: LogViewerProps) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  
  // Filters
  const [levelFilter, setLevelFilter] = useState<Set<LogLevel>>(
    new Set(['debug', 'info', 'warning', 'error', 'critical'])
  )
  const [moduleFilter, setModuleFilter] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [timeRange, setTimeRange] = useState<'all' | '1h' | '6h' | '24h'>('all')
  
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  
  // Connect to WebSocket
  useEffect(() => {
    const websocket = new WebSocket(websocketUrl)
    
    websocket.onopen = () => {
      console.log('[LogViewer] WebSocket connected')
      setIsConnected(true)
    }
    
    websocket.onmessage = (event) => {
      if (isPaused) return
      
      try {
        const data = JSON.parse(event.data)
        
        if (data.type === 'log') {
          const logEntry: LogEntry = {
            id: data.id || `${Date.now()}-${Math.random()}`,
            timestamp: data.timestamp || new Date().toISOString(),
            level: data.level || 'info',
            module: data.module || 'unknown',
            message: data.message,
            metadata: data.metadata,
            request: data.request,
            response: data.response
          }
          
          setLogs(prev => {
            const newLogs = [logEntry, ...prev]
            return newLogs.slice(0, maxLogs)
          })
        }
      } catch (error) {
        console.error('[LogViewer] Error parsing message:', error)
      }
    }
    
    websocket.onerror = (error) => {
      console.error('[LogViewer] WebSocket error:', error)
    }
    
    websocket.onclose = () => {
      console.log('[LogViewer] WebSocket disconnected')
      setIsConnected(false)
    }
    
    return () => {
      websocket.close()
    }
  }, [websocketUrl, isPaused, maxLogs])
  
  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])
  
  // Get log level color
  const getLevelColor = (level: LogLevel): string => {
    switch (level) {
      case 'debug': return 'text-gray-600 bg-gray-100'
      case 'info': return 'text-blue-600 bg-blue-100'
      case 'warning': return 'text-yellow-600 bg-yellow-100'
      case 'error': return 'text-red-600 bg-red-100'
      case 'critical': return 'text-red-700 bg-red-200 font-bold'
      default: return 'text-gray-600 bg-gray-100'
    }
  }
  
  // Filter logs
  const filteredLogs = logs.filter(log => {
    // Level filter
    if (!levelFilter.has(log.level)) return false
    
    // Module filter
    if (moduleFilter && !log.module.toLowerCase().includes(moduleFilter.toLowerCase())) {
      return false
    }
    
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      if (!log.message.toLowerCase().includes(query) &&
          !log.module.toLowerCase().includes(query)) {
        return false
      }
    }
    
    // Time range filter
    if (timeRange !== 'all') {
      const logTime = new Date(log.timestamp).getTime()
      const now = Date.now()
      const ranges = {
        '1h': 3600000,
        '6h': 21600000,
        '24h': 86400000
      }
      if (now - logTime > ranges[timeRange]) {
        return false
      }
    }
    
    return true
  })
  
  // Toggle level filter
  const toggleLevelFilter = (level: LogLevel) => {
    setLevelFilter(prev => {
      const newSet = new Set(prev)
      if (newSet.has(level)) {
        newSet.delete(level)
      } else {
        newSet.add(level)
      }
      return newSet
    })
  }
  
  // Export logs
  const exportLogs = (format: 'json' | 'csv') => {
    if (format === 'json') {
      const dataStr = JSON.stringify(filteredLogs, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `logs-${new Date().toISOString()}.json`
      link.click()
    } else if (format === 'csv') {
      const headers = ['Timestamp', 'Level', 'Module', 'Message']
      const rows = filteredLogs.map(log => [
        log.timestamp,
        log.level,
        log.module,
        log.message.replace(/"/g, '""')
      ])
      
      const csv = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
      ].join('\n')
      
      const dataBlob = new Blob([csv], { type: 'text/csv' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `logs-${new Date().toISOString()}.csv`
      link.click()
    }
  }
  
  // Clear logs
  const clearLogs = () => {
    if (confirm('Clear all logs?')) {
      setLogs([])
      setSelectedLog(null)
    }
  }
  
  // Get unique modules
  const uniqueModules = Array.from(new Set(logs.map(log => log.module))).sort()
  
  return (
    <div className="log-viewer h-full flex flex-col">
      {/* Header */}
      <div className="border-b p-4 bg-white">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-semibold">Log Viewer</h2>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-600">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            {isPaused && (
              <span className="px-2 py-1 text-xs bg-yellow-100 text-yellow-700 rounded">
                Paused
              </span>
            )}
          </div>
          
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span>Total: {logs.length}</span>
            <span>•</span>
            <span>Filtered: {filteredLogs.length}</span>
          </div>
        </div>
        
        {/* Filters */}
        <div className="space-y-3">
          {/* Level filter */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-gray-700">Level:</span>
            {(['debug', 'info', 'warning', 'error', 'critical'] as LogLevel[]).map(level => (
              <button
                key={level}
                onClick={() => toggleLevelFilter(level)}
                className={`px-3 py-1 text-sm rounded capitalize ${
                  levelFilter.has(level)
                    ? getLevelColor(level)
                    : 'text-gray-400 bg-gray-100'
                }`}
              >
                {level}
              </button>
            ))}
          </div>
          
          {/* Search and filters */}
          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 px-3 py-1 text-sm border rounded"
            />
            
            <select
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
              className="px-3 py-1 text-sm border rounded"
            >
              <option value="">All Modules</option>
              {uniqueModules.map(module => (
                <option key={module} value={module}>{module}</option>
              ))}
            </select>
            
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value as any)}
              className="px-3 py-1 text-sm border rounded"
            >
              <option value="all">All Time</option>
              <option value="1h">Last Hour</option>
              <option value="6h">Last 6 Hours</option>
              <option value="24h">Last 24 Hours</option>
            </select>
          </div>
          
          {/* Controls */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsPaused(!isPaused)}
              className={`px-3 py-1 text-sm rounded ${
                isPaused ? 'bg-yellow-600 text-white' : 'bg-gray-200 text-gray-700'
              }`}
            >
              {isPaused ? '▶️ Resume' : '⏸️ Pause'}
            </button>
            
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="autoScroll"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded"
              />
              <label htmlFor="autoScroll" className="text-sm text-gray-700">
                Auto-scroll
              </label>
            </div>
            
            <div className="flex items-center gap-2 ml-auto">
              <button
                onClick={() => exportLogs('json')}
                className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
              >
                Export JSON
              </button>
              <button
                onClick={() => exportLogs('csv')}
                className="px-3 py-1 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
              >
                Export CSV
              </button>
              <button
                onClick={clearLogs}
                className="px-3 py-1 text-sm text-red-600 hover:text-red-800"
              >
                Clear
              </button>
            </div>
          </div>
        </div>
      </div>
      
      {/* Logs List */}
      <div 
        ref={logsContainerRef}
        className="flex-1 overflow-auto font-mono text-sm"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <div className="text-4xl mb-2">📋</div>
            <div>No logs to display</div>
            {logs.length > 0 && (
              <div className="text-sm mt-1">Try adjusting your filters</div>
            )}
          </div>
        ) : (
          <div className="divide-y">
            {filteredLogs.map((log) => (
              <div
                key={log.id}
                onClick={() => setSelectedLog(log)}
                className="p-3 hover:bg-gray-50 cursor-pointer"
              >
                <div className="flex items-start gap-3">
                  <span className="text-xs text-gray-500 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                  
                  <span className={`px-2 py-0.5 text-xs rounded uppercase ${getLevelColor(log.level)}`}>
                    {log.level}
                  </span>
                  
                  <span className="text-xs text-gray-600 whitespace-nowrap">
                    [{log.module}]
                  </span>
                  
                  <span className="flex-1 text-sm">
                    {log.message}
                  </span>
                  
                  {log.response && (
                    <span className={`text-xs whitespace-nowrap ${
                      log.response.status >= 200 && log.response.status < 300
                        ? 'text-green-600'
                        : log.response.status >= 400
                        ? 'text-red-600'
                        : 'text-yellow-600'
                    }`}>
                      {log.response.status} • {log.response.time.toFixed(0)}ms
                    </span>
                  )}
                </div>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        )}
      </div>
      
      {/* Detail Modal */}
      {selectedLog && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedLog(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Log Details</h3>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                {/* Summary */}
                <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded">
                  <div>
                    <div className="text-sm text-gray-600">Timestamp</div>
                    <div className="font-medium">{new Date(selectedLog.timestamp).toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Level</div>
                    <div className={`inline-block px-2 py-1 rounded text-sm ${getLevelColor(selectedLog.level)}`}>
                      {selectedLog.level.toUpperCase()}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Module</div>
                    <div className="font-medium">{selectedLog.module}</div>
                  </div>
                  {selectedLog.response && (
                    <div>
                      <div className="text-sm text-gray-600">Response</div>
                      <div className="font-medium">
                        {selectedLog.response.status} • {selectedLog.response.length} bytes • {selectedLog.response.time.toFixed(2)}ms
                      </div>
                    </div>
                  )}
                </div>
                
                {/* Message */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Message</div>
                  <div className="p-4 bg-gray-50 rounded font-mono text-sm">
                    {selectedLog.message}
                  </div>
                </div>
                
                {/* Request */}
                {selectedLog.request && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Request</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                      {selectedLog.request.method} {selectedLog.request.url}
                      {selectedLog.request.headers && '\n' + Object.entries(selectedLog.request.headers)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join('\n')}
                    </pre>
                  </div>
                )}
                
                {/* Metadata */}
                {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Metadata</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                      {JSON.stringify(selectedLog.metadata, null, 2)}
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
