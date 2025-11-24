/**
 * JWT Inspector Component
 * 
 * Automatic JWT detection, decoding, and manipulation with:
 * - Auto-detect JWTs from headers and cookies
 * - Decode header and payload claims
 * - Edit any claim value
 * - One-click tampering (alg:none, signature removal)
 * - kid and jwk parameter editing
 */

import { useState, useEffect } from 'react'

interface JWTToken {
  id: string
  raw: string
  header: Record<string, any>
  payload: Record<string, any>
  signature: string
  source: 'header' | 'cookie' | 'manual'
  sourceName?: string
}

interface JWTInspectorProps {
  onTokenModified?: (original: string, modified: string) => void
}

export default function JWTInspector({ onTokenModified }: JWTInspectorProps) {
  const [tokens, setTokens] = useState<JWTToken[]>([])
  const [selectedToken, setSelectedToken] = useState<JWTToken | null>(null)
  const [editedHeader, setEditedHeader] = useState<string>('')
  const [editedPayload, setEditedPayload] = useState<string>('')
  const [manualInput, setManualInput] = useState<string>('')
  const [error, setError] = useState<string>('')
  
  // Decode JWT
  const decodeJWT = (token: string): { header: any; payload: any; signature: string } | null => {
    try {
      const parts = token.split('.')
      if (parts.length !== 3) {
        return null
      }
      
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
      const signature = parts[2]
      
      return { header, payload, signature }
    } catch {
      return null
    }
  }
  
  // Encode JWT
  const encodeJWT = (header: any, payload: any, signature: string = ''): string => {
    const base64UrlEncode = (obj: any): string => {
      const json = JSON.stringify(obj)
      return btoa(json)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
    }
    
    const encodedHeader = base64UrlEncode(header)
    const encodedPayload = base64UrlEncode(payload)
    
    return `${encodedHeader}.${encodedPayload}.${signature}`
  }
  
  // Add token manually
  const addManualToken = () => {
    if (!manualInput.trim()) {
      setError('Please enter a JWT token')
      return
    }
    
    const decoded = decodeJWT(manualInput.trim())
    if (!decoded) {
      setError('Invalid JWT format')
      return
    }
    
    const newToken: JWTToken = {
      id: `manual-${Date.now()}`,
      raw: manualInput.trim(),
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      source: 'manual'
    }
    
    setTokens([newToken, ...tokens])
    setManualInput('')
    setError('')
  }
  
  // Select token for editing
  const selectToken = (token: JWTToken) => {
    setSelectedToken(token)
    setEditedHeader(JSON.stringify(token.header, null, 2))
    setEditedPayload(JSON.stringify(token.payload, null, 2))
    setError('')
  }
  
  // Apply algorithm confusion (alg: none)
  const applyAlgNone = () => {
    if (!selectedToken) return
    
    try {
      const header = JSON.parse(editedHeader)
      header.alg = 'none'
      
      const newToken = encodeJWT(header, JSON.parse(editedPayload), '')
      
      onTokenModified?.(selectedToken.raw, newToken)
      
      // Update token in list
      const updatedToken: JWTToken = {
        ...selectedToken,
        raw: newToken,
        header,
        signature: ''
      }
      
      setTokens(tokens.map(t => t.id === selectedToken.id ? updatedToken : t))
      setSelectedToken(updatedToken)
      setEditedHeader(JSON.stringify(header, null, 2))
    } catch (err) {
      setError('Invalid JSON in header or payload')
    }
  }
  
  // Remove signature
  const removeSignature = () => {
    if (!selectedToken) return
    
    try {
      const header = JSON.parse(editedHeader)
      const payload = JSON.parse(editedPayload)
      
      const newToken = encodeJWT(header, payload, '')
      
      onTokenModified?.(selectedToken.raw, newToken)
      
      const updatedToken: JWTToken = {
        ...selectedToken,
        raw: newToken,
        signature: ''
      }
      
      setTokens(tokens.map(t => t.id === selectedToken.id ? updatedToken : t))
      setSelectedToken(updatedToken)
    } catch (err) {
      setError('Invalid JSON in header or payload')
    }
  }
  
  // Apply custom modifications
  const applyModifications = () => {
    if (!selectedToken) return
    
    try {
      const header = JSON.parse(editedHeader)
      const payload = JSON.parse(editedPayload)
      
      const newToken = encodeJWT(header, payload, selectedToken.signature)
      
      onTokenModified?.(selectedToken.raw, newToken)
      
      const updatedToken: JWTToken = {
        ...selectedToken,
        raw: newToken,
        header,
        payload
      }
      
      setTokens(tokens.map(t => t.id === selectedToken.id ? updatedToken : t))
      setSelectedToken(updatedToken)
      setError('')
    } catch (err) {
      setError('Invalid JSON in header or payload')
    }
  }
  
  // Quick edit claim
  const quickEditClaim = (claimName: string, newValue: any) => {
    if (!selectedToken) return
    
    try {
      const payload = JSON.parse(editedPayload)
      payload[claimName] = newValue
      setEditedPayload(JSON.stringify(payload, null, 2))
    } catch (err) {
      setError('Invalid JSON in payload')
    }
  }
  
  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }
  
  // Delete token
  const deleteToken = (id: string) => {
    setTokens(tokens.filter(t => t.id !== id))
    if (selectedToken?.id === id) {
      setSelectedToken(null)
    }
  }
  
  return (
    <div className="jwt-inspector h-full flex flex-col">
      {/* Header */}
      <div className="border-b p-4 bg-white">
        <h2 className="text-xl font-semibold mb-4">JWT Inspector</h2>
        
        {/* Manual Input */}
        <div className="flex gap-2">
          <input
            type="text"
            value={manualInput}
            onChange={(e) => setManualInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && addManualToken()}
            placeholder="Paste JWT token here..."
            className="flex-1 px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
          />
          <button
            onClick={addManualToken}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Add Token
          </button>
        </div>
        
        {error && (
          <div className="mt-2 text-sm text-red-600">{error}</div>
        )}
        
        <div className="mt-2 text-sm text-gray-600">
          Detected Tokens: {tokens.length}
        </div>
      </div>
      
      <div className="flex-1 flex overflow-hidden">
        {/* Token List */}
        <div className="w-80 border-r overflow-auto bg-gray-50">
          {tokens.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <div className="text-4xl mb-2">🔐</div>
              <div>No JWT tokens detected</div>
              <div className="text-sm mt-1">Add a token manually or they will be auto-detected</div>
            </div>
          ) : (
            <div className="divide-y">
              {tokens.map((token) => (
                <div
                  key={token.id}
                  onClick={() => selectToken(token)}
                  className={`p-4 cursor-pointer hover:bg-gray-100 ${
                    selectedToken?.id === token.id ? 'bg-blue-50 border-l-4 border-blue-600' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${
                      token.source === 'header' 
                        ? 'bg-purple-100 text-purple-700'
                        : token.source === 'cookie'
                        ? 'bg-green-100 text-green-700'
                        : 'bg-gray-100 text-gray-700'
                    }`}>
                      {token.source}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        deleteToken(token.id)
                      }}
                      className="text-gray-400 hover:text-red-600"
                    >
                      ✕
                    </button>
                  </div>
                  
                  {token.sourceName && (
                    <div className="text-xs text-gray-600 mb-2">{token.sourceName}</div>
                  )}
                  
                  <div className="text-xs font-mono text-gray-500 truncate">
                    {token.raw.substring(0, 50)}...
                  </div>
                  
                  <div className="mt-2 text-xs text-gray-600">
                    alg: {token.header.alg || 'none'}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        
        {/* Token Editor */}
        {selectedToken ? (
          <div className="flex-1 overflow-auto p-6">
            <div className="max-w-4xl mx-auto space-y-6">
              {/* Quick Actions */}
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={applyAlgNone}
                  className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 text-sm"
                >
                  🔓 Algorithm Confusion (alg: none)
                </button>
                <button
                  onClick={removeSignature}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm"
                >
                  ✂️ Remove Signature
                </button>
                <button
                  onClick={() => copyToClipboard(selectedToken.raw)}
                  className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm"
                >
                  📋 Copy Original
                </button>
              </div>
              
              {/* Quick Edits */}
              <div className="p-4 bg-blue-50 rounded-lg">
                <div className="text-sm font-medium text-blue-900 mb-3">Quick Claim Edits</div>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => quickEditClaim('isAdmin', true)}
                    className="px-3 py-2 bg-white border border-blue-200 rounded text-sm hover:bg-blue-50"
                  >
                    Set isAdmin: true
                  </button>
                  <button
                    onClick={() => quickEditClaim('role', 'admin')}
                    className="px-3 py-2 bg-white border border-blue-200 rounded text-sm hover:bg-blue-50"
                  >
                    Set role: admin
                  </button>
                  <button
                    onClick={() => quickEditClaim('exp', Math.floor(Date.now() / 1000) + 86400)}
                    className="px-3 py-2 bg-white border border-blue-200 rounded text-sm hover:bg-blue-50"
                  >
                    Extend expiry (+24h)
                  </button>
                  <button
                    onClick={() => quickEditClaim('iat', Math.floor(Date.now() / 1000))}
                    className="px-3 py-2 bg-white border border-blue-200 rounded text-sm hover:bg-blue-50"
                  >
                    Update issued time
                  </button>
                </div>
              </div>
              
              {/* Header Editor */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm font-medium text-gray-700">Header</label>
                  <div className="text-xs text-gray-500">
                    Algorithm: {selectedToken.header.alg || 'none'}
                  </div>
                </div>
                <textarea
                  value={editedHeader}
                  onChange={(e) => setEditedHeader(e.target.value)}
                  className="w-full h-40 px-3 py-2 border rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  spellCheck={false}
                />
              </div>
              
              {/* Payload Editor */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="text-sm font-medium text-gray-700">Payload</label>
                  <div className="text-xs text-gray-500">
                    {Object.keys(selectedToken.payload).length} claims
                  </div>
                </div>
                <textarea
                  value={editedPayload}
                  onChange={(e) => setEditedPayload(e.target.value)}
                  className="w-full h-64 px-3 py-2 border rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  spellCheck={false}
                />
              </div>
              
              {/* Signature */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Signature</label>
                <div className="px-3 py-2 bg-gray-50 rounded-lg font-mono text-sm break-all">
                  {selectedToken.signature || '(no signature)'}
                </div>
              </div>
              
              {/* Apply Button */}
              <div className="flex gap-3">
                <button
                  onClick={applyModifications}
                  className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
                >
                  Apply Modifications
                </button>
                <button
                  onClick={() => {
                    const newToken = encodeJWT(
                      JSON.parse(editedHeader),
                      JSON.parse(editedPayload),
                      selectedToken.signature
                    )
                    copyToClipboard(newToken)
                  }}
                  className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                >
                  Copy Modified Token
                </button>
              </div>
              
              {/* Modified Token Display */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Modified Token (will be used in requests)
                </label>
                <div className="px-3 py-2 bg-green-50 border border-green-200 rounded-lg font-mono text-xs break-all">
                  {selectedToken.raw}
                </div>
              </div>
              
              {/* Decoded Info */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-700 mb-2">Common Claims</div>
                  <div className="space-y-1 text-sm">
                    {selectedToken.payload.sub && (
                      <div><span className="text-gray-600">Subject:</span> {selectedToken.payload.sub}</div>
                    )}
                    {selectedToken.payload.iss && (
                      <div><span className="text-gray-600">Issuer:</span> {selectedToken.payload.iss}</div>
                    )}
                    {selectedToken.payload.aud && (
                      <div><span className="text-gray-600">Audience:</span> {selectedToken.payload.aud}</div>
                    )}
                    {selectedToken.payload.exp && (
                      <div>
                        <span className="text-gray-600">Expires:</span>{' '}
                        {new Date(selectedToken.payload.exp * 1000).toLocaleString()}
                      </div>
                    )}
                    {selectedToken.payload.iat && (
                      <div>
                        <span className="text-gray-600">Issued:</span>{' '}
                        {new Date(selectedToken.payload.iat * 1000).toLocaleString()}
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="text-sm font-medium text-gray-700 mb-2">Security Info</div>
                  <div className="space-y-1 text-sm">
                    <div>
                      <span className="text-gray-600">Algorithm:</span>{' '}
                      <span className={selectedToken.header.alg === 'none' ? 'text-red-600 font-medium' : ''}>
                        {selectedToken.header.alg || 'none'}
                      </span>
                    </div>
                    {selectedToken.header.kid && (
                      <div><span className="text-gray-600">Key ID:</span> {selectedToken.header.kid}</div>
                    )}
                    {selectedToken.header.typ && (
                      <div><span className="text-gray-600">Type:</span> {selectedToken.header.typ}</div>
                    )}
                    <div>
                      <span className="text-gray-600">Signature:</span>{' '}
                      {selectedToken.signature ? 'Present' : 'Missing'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-gray-500">
            <div className="text-center">
              <div className="text-4xl mb-2">👈</div>
              <div>Select a token to inspect and modify</div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
