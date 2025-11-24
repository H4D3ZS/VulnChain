/**
 * OOB (Out-of-Band) Listener Component
 * 
 * Displays incoming DNS/HTTP callbacks with:
 * - Real-time WebSocket updates
 * - Automatic flag extraction and highlighting
 * - Auto-decode for base64/URL encoding
 * - Connection details (IP, timestamp, data)
 */

import { useState, useEffect } from 'react'

interface OOBCallback {
  id: string
  type: 'http' | 'dns'
  sourceIp: string
  timestamp: string
  data: string
  decodedData?: string
  flags?: string[]
  correlationId?: string
  headers?: Record<string, string>
  method?: string
  path?: string
}

interface OOBListenerProps {
  websocketUrl?: string
  onCallbackReceived?: (callback: OOBCallback) => void
}

export default function OOBListener({
  websocketUrl = 'ws://localhost:8000/ws/oob',
  onCallbackReceived
}: OOBListenerProps) {
  const [callbacks, setCallbacks] = useState<OOBCallback[]>([])
  const [selectedCallback, setSelectedCallback] = useState<OOBCallback | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [isListening, setIsListening] = useState(false)
  const [listenerUrl, setListenerUrl] = useState('')
  const [autoDecode, setAutoDecode] = useState(true)
  const [filter, setFilter] = useState<'all' | 'http' | 'dns'>('all')
  
  // Connect to WebSocket
  useEffect(() => {
    const websocket = new WebSocket(websocketUrl)
    
    websocket.onopen = () => {
      console.log('[OOBListener] WebSocket connected')
      setIsConnected(true)
    }
    
    websocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        
        if (data.type === 'oob_callback') {
          const callback: OOBCallback = {
            id: data.id || `${Date.now()}-${Math.random()}`,
            type: data.callback_type || 'http',
            sourceIp: data.source_ip,
            timestamp: data.timestamp || new Date().toISOString(),
            data: data.data,
            decodedData: data.decoded_data,
            flags: data.flags || [],
            correlationId: data.correlation_id,
            headers: data.headers,
            method: data.method,
            path: data.path
          }
          
          // Auto-decode if enabled
          if (autoDecode && !callback.decodedData) {
            callback.decodedData = tryDecode(callback.data)
          }
          
          setCallbacks(prev => [callback, ...prev])
          onCallbackReceived?.(callback)
          
          // Show notification for new callback
          if (Notification.permission === 'granted') {
            new Notification('OOB Callback Received', {
              body: `${callback.type.toUpperCase()} from ${callback.sourceIp}`,
              icon: '/favicon.ico'
            })
          }
        } else if (data.type === 'listener_status') {
          setIsListening(data.is_listening)
          setListenerUrl(data.url || '')
        }
      } catch (error) {
        console.error('[OOBListener] Error parsing message:', error)
      }
    }
    
    websocket.onerror = (error) => {
      console.error('[OOBListener] WebSocket error:', error)
    }
    
    websocket.onclose = () => {
      console.log('[OOBListener] WebSocket disconnected')
      setIsConnected(false)
    }
    
    return () => {
      websocket.close()
    }
  }, [websocketUrl, autoDecode, onCallbackReceived])
  
  // Request notification permission
  useEffect(() => {
    if (Notification.permission === 'default') {
      Notification.requestPermission()
    }
  }, [])
  
  // Try to decode data
  const tryDecode = (data: string): string => {
    try {
      // Try base64
      const base64Decoded = atob(data)
      if (isPrintable(base64Decoded)) {
        return `[Base64] ${base64Decoded}`
      }
    } catch {}
    
    try {
      // Try URL decode
      const urlDecoded = decodeURIComponent(data)
      if (urlDecoded !== data) {
        return `[URL] ${urlDecoded}`
      }
    } catch {}
    
    return data
  }
  
  // Check if string is printable
  const isPrintable = (str: string): boolean => {
    return /^[\x20-\x7E\s]*$/.test(str)
  }
  
  // Extract flags from text
  const extractFlags = (text: string): string[] => {
    const flagPatterns = [
      /CTF\{[^\}]+\}/g,
      /FLAG\{[^\}]+\}/g,
      /HTB\{[^\}]+\}/g,
      /flag\{[^\}]+\}/g,
      /[A-Za-z0-9]{32}/g
    ]
    
    const flags: string[] = []
    for (const pattern of flagPatterns) {
      const matches = text.match(pattern)
      if (matches) {
        flags.push(...matches)
      }
    }
    
    return [...new Set(flags)]
  }
  
  // Highlight flags in text
  const highlightFlags = (text: string): JSX.Element => {
    const flags = extractFlags(text)
    if (flags.length === 0) {
      return <span>{text}</span>
    }
    
    let result = text
    const parts: JSX.Element[] = []
    let lastIndex = 0
    
    flags.forEach((flag, i) => {
      const index = result.indexOf(flag, lastIndex)
      if (index !== -1) {
        // Add text before flag
        if (index > lastIndex) {
          parts.push(<span key={`text-${i}`}>{result.substring(lastIndex, index)}</span>)
        }
        // Add highlighted flag
        parts.push(
          <span key={`flag-${i}`} className="bg-yellow-200 font-bold px-1 rounded">
            {flag}
          </span>
        )
        lastIndex = index + flag.length
      }
    })
    
    // Add remaining text
    if (lastIndex < result.length) {
      parts.push(<span key="text-end">{result.substring(lastIndex)}</span>)
    }
    
    return <>{parts}</>
  }
  
  // Filter callbacks
  const filteredCallbacks = callbacks.filter(cb => 
    filter === 'all' || cb.type === filter
  )
  
  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }
  
  return (
    <div className="oob-listener h-full flex flex-col">
      {/* Header */}
      <div className="border-b p-4 bg-white">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-semibold">OOB Listener</h2>
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm text-gray-600">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            {isListening && (
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                <span className="text-sm text-blue-600 font-medium">Listening</span>
              </div>
            )}
          </div>
          
          <div className="text-sm text-gray-600">
            Total Callbacks: {callbacks.length}
          </div>
        </div>
        
        {/* Listener URL */}
        {listenerUrl && (
          <div className="mb-4 p-3 bg-blue-50 rounded-lg">
            <div className="text-sm font-medium text-blue-900 mb-1">Listener URL:</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-sm font-mono text-blue-700">{listenerUrl}</code>
              <button
                onClick={() => copyToClipboard(listenerUrl)}
                className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Copy
              </button>
            </div>
          </div>
        )}
        
        {/* Controls */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-700">Filter:</span>
            <button
              onClick={() => setFilter('all')}
              className={`px-3 py-1 text-sm rounded ${
                filter === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('http')}
              className={`px-3 py-1 text-sm rounded ${
                filter === 'http' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'
              }`}
            >
              HTTP
            </button>
            <button
              onClick={() => setFilter('dns')}
              className={`px-3 py-1 text-sm rounded ${
                filter === 'dns' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-700'
              }`}
            >
              DNS
            </button>
          </div>
          
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="autoDecode"
              checked={autoDecode}
              onChange={(e) => setAutoDecode(e.target.checked)}
              className="rounded"
            />
            <label htmlFor="autoDecode" className="text-sm font-medium text-gray-700">
              Auto-decode
            </label>
          </div>
          
          <button
            onClick={() => setCallbacks([])}
            className="ml-auto px-3 py-1 text-sm text-gray-600 hover:text-gray-800"
          >
            Clear All
          </button>
        </div>
      </div>
      
      {/* Callbacks List */}
      <div className="flex-1 overflow-auto">
        {filteredCallbacks.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <div className="text-4xl mb-2">📡</div>
            <div>No callbacks received yet</div>
            <div className="text-sm mt-1">Waiting for OOB connections...</div>
          </div>
        ) : (
          <div className="divide-y">
            {filteredCallbacks.map((callback) => (
              <div
                key={callback.id}
                onClick={() => setSelectedCallback(callback)}
                className="p-4 hover:bg-gray-50 cursor-pointer"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${
                      callback.type === 'http' 
                        ? 'bg-blue-100 text-blue-700' 
                        : 'bg-purple-100 text-purple-700'
                    }`}>
                      {callback.type.toUpperCase()}
                    </span>
                    <span className="text-sm font-medium text-gray-900">
                      {callback.sourceIp}
                    </span>
                    {callback.correlationId && (
                      <span className="text-xs text-gray-500">
                        ID: {callback.correlationId}
                      </span>
                    )}
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(callback.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                
                {callback.method && callback.path && (
                  <div className="text-sm text-gray-600 mb-2">
                    {callback.method} {callback.path}
                  </div>
                )}
                
                <div className="text-sm font-mono bg-gray-50 p-2 rounded overflow-x-auto">
                  {highlightFlags(callback.decodedData || callback.data)}
                </div>
                
                {callback.flags && callback.flags.length > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-xs font-medium text-green-700">🚩 Flags:</span>
                    {callback.flags.map((flag, i) => (
                      <span key={i} className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">
                        {flag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Detail Modal */}
      {selectedCallback && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedCallback(null)}
        >
          <div 
            className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">Callback Details</h3>
                <button
                  onClick={() => setSelectedCallback(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                {/* Summary */}
                <div className="grid grid-cols-2 gap-4 p-4 bg-gray-50 rounded">
                  <div>
                    <div className="text-sm text-gray-600">Type</div>
                    <div className="font-medium">{selectedCallback.type.toUpperCase()}</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Source IP</div>
                    <div className="font-medium">{selectedCallback.sourceIp}</div>
                  </div>
                  <div>
                    <div className="text-sm text-gray-600">Timestamp</div>
                    <div className="font-medium">{new Date(selectedCallback.timestamp).toLocaleString()}</div>
                  </div>
                  {selectedCallback.correlationId && (
                    <div>
                      <div className="text-sm text-gray-600">Correlation ID</div>
                      <div className="font-medium font-mono text-sm">{selectedCallback.correlationId}</div>
                    </div>
                  )}
                </div>
                
                {/* Request Details */}
                {selectedCallback.method && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Request</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono">
                      {selectedCallback.method} {selectedCallback.path}
                    </pre>
                  </div>
                )}
                
                {/* Headers */}
                {selectedCallback.headers && Object.keys(selectedCallback.headers).length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Headers</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                      {Object.entries(selectedCallback.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                    </pre>
                  </div>
                )}
                
                {/* Data */}
                <div>
                  <div className="text-sm font-medium text-gray-700 mb-2">Data</div>
                  <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                    {selectedCallback.data}
                  </pre>
                </div>
                
                {/* Decoded Data */}
                {selectedCallback.decodedData && selectedCallback.decodedData !== selectedCallback.data && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Decoded Data</div>
                    <pre className="p-4 bg-gray-50 rounded text-xs font-mono overflow-x-auto">
                      {selectedCallback.decodedData}
                    </pre>
                  </div>
                )}
                
                {/* Flags */}
                {selectedCallback.flags && selectedCallback.flags.length > 0 && (
                  <div>
                    <div className="text-sm font-medium text-gray-700 mb-2">Extracted Flags</div>
                    <div className="space-y-2">
                      {selectedCallback.flags.map((flag, i) => (
                        <div key={i} className="flex items-center gap-2 p-3 bg-green-50 rounded">
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
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
