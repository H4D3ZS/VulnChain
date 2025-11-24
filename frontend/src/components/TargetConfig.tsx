/**
 * Target Configuration Panel
 * 
 * Form for configuring attack targets with:
 * - URL input with validation
 * - Custom headers (key-value pairs)
 * - Proxy URL configuration
 * - WAF bypass profile selection
 * - Save/load configuration
 */

import { useState, useEffect } from 'react'
import { createTarget, getTargets } from '../services/api'

interface Header {
  id: string
  key: string
  value: string
}

interface TargetConfigData {
  url: string
  customHeaders: Record<string, string>
  proxy: string
  wafBypassProfile: string
  name?: string
  description?: string
}

interface TargetConfigProps {
  onSave?: (config: TargetConfigData) => void
  initialConfig?: TargetConfigData
}

const WAF_PROFILES = [
  { value: '', label: 'None' },
  { value: 'cloudflare', label: 'Cloudflare' },
  { value: 'akamai', label: 'Akamai' },
  { value: 'aws_waf', label: 'AWS WAF' },
  { value: 'modsecurity', label: 'ModSecurity' },
  { value: 'generic', label: 'Generic' },
]

export default function TargetConfig({ onSave, initialConfig }: TargetConfigProps) {
  const [url, setUrl] = useState(initialConfig?.url || '')
  const [urlError, setUrlError] = useState('')
  const [headers, setHeaders] = useState<Header[]>(() => {
    if (initialConfig?.customHeaders) {
      return Object.entries(initialConfig.customHeaders).map(([key, value], index) => ({
        id: `header-${index}`,
        key,
        value
      }))
    }
    return []
  })
  const [proxy, setProxy] = useState(initialConfig?.proxy || '')
  const [proxyError, setProxyError] = useState('')
  const [wafProfile, setWafProfile] = useState(initialConfig?.wafBypassProfile || '')
  const [name, setName] = useState(initialConfig?.name || '')
  const [description, setDescription] = useState(initialConfig?.description || '')
  const [isSaving, setIsSaving] = useState(false)
  
  // Validate URL
  const validateUrl = (value: string): boolean => {
    if (!value) {
      setUrlError('URL is required')
      return false
    }
    
    try {
      const urlObj = new URL(value)
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        setUrlError('URL must use http:// or https://')
        return false
      }
      setUrlError('')
      return true
    } catch {
      setUrlError('Invalid URL format')
      return false
    }
  }
  
  // Validate proxy URL
  const validateProxy = (value: string): boolean => {
    if (!value) {
      setProxyError('')
      return true
    }
    
    try {
      const urlObj = new URL(value)
      if (!['http:', 'https:', 'socks5:'].includes(urlObj.protocol)) {
        setProxyError('Proxy must use http://, https://, or socks5://')
        return false
      }
      setProxyError('')
      return true
    } catch {
      setProxyError('Invalid proxy URL format')
      return false
    }
  }
  
  // Add header
  const addHeader = () => {
    setHeaders([...headers, { id: `header-${Date.now()}`, key: '', value: '' }])
  }
  
  // Update header
  const updateHeader = (id: string, field: 'key' | 'value', value: string) => {
    setHeaders(headers.map(h => 
      h.id === id ? { ...h, [field]: value } : h
    ))
  }
  
  // Remove header
  const removeHeader = (id: string) => {
    setHeaders(headers.filter(h => h.id !== id))
  }
  
  // Handle save
  const handleSave = async () => {
    // Validate
    if (!validateUrl(url)) return
    if (!validateProxy(proxy)) return
    
    // Convert headers to object
    const customHeaders: Record<string, string> = {}
    headers.forEach(h => {
      if (h.key && h.value) {
        customHeaders[h.key] = h.value
      }
    })
    
    const config = {
      url,
      custom_headers: customHeaders,
      proxy: proxy || undefined,
      waf_bypass_profile: wafProfile || undefined,
      name: name || undefined,
      description: description || undefined
    }
    
    setIsSaving(true)
    try {
      await createTarget(config)
      alert('Target configuration saved successfully!')
      onSave?.(config as any)
    } catch (err: any) {
      console.error('Failed to save target:', err)
      alert(err.response?.data?.detail || 'Failed to save target configuration')
    } finally {
      setIsSaving(false)
    }
  }
  
  // Load common headers
  const loadCommonHeaders = (type: string) => {
    const commonHeaders: Record<string, Header[]> = {
      json: [
        { id: `header-${Date.now()}-1`, key: 'Content-Type', value: 'application/json' },
        { id: `header-${Date.now()}-2`, key: 'Accept', value: 'application/json' }
      ],
      form: [
        { id: `header-${Date.now()}-1`, key: 'Content-Type', value: 'application/x-www-form-urlencoded' }
      ],
      ajax: [
        { id: `header-${Date.now()}-1`, key: 'X-Requested-With', value: 'XMLHttpRequest' }
      ],
      auth: [
        { id: `header-${Date.now()}-1`, key: 'Authorization', value: 'Bearer YOUR_TOKEN_HERE' }
      ]
    }
    
    if (commonHeaders[type]) {
      setHeaders([...headers, ...commonHeaders[type]])
    }
  }
  
  return (
    <div className="target-config p-6 bg-white rounded-lg shadow">
      <h2 className="text-2xl font-semibold mb-6">Target Configuration</h2>
      
      <div className="space-y-6">
        {/* Name and Description */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Configuration Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Target Config"
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description
            </label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
        </div>
        
        {/* Target URL */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Target URL *
          </label>
          <input
            type="url"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value)
              validateUrl(e.target.value)
            }}
            onBlur={() => validateUrl(url)}
            placeholder="https://example.com"
            className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
              urlError ? 'border-red-500' : ''
            }`}
          />
          {urlError && (
            <p className="mt-1 text-sm text-red-600">{urlError}</p>
          )}
          <p className="mt-1 text-sm text-gray-500">
            The base URL of the target application
          </p>
        </div>
        
        {/* Custom Headers */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="block text-sm font-medium text-gray-700">
              Custom Headers
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => loadCommonHeaders('json')}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                + JSON
              </button>
              <button
                onClick={() => loadCommonHeaders('form')}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                + Form
              </button>
              <button
                onClick={() => loadCommonHeaders('ajax')}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                + AJAX
              </button>
              <button
                onClick={() => loadCommonHeaders('auth')}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                + Auth
              </button>
            </div>
          </div>
          
          <div className="space-y-2">
            {headers.map((header) => (
              <div key={header.id} className="flex gap-2">
                <input
                  type="text"
                  value={header.key}
                  onChange={(e) => updateHeader(header.id, 'key', e.target.value)}
                  placeholder="Header-Name"
                  className="flex-1 px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <input
                  type="text"
                  value={header.value}
                  onChange={(e) => updateHeader(header.id, 'value', e.target.value)}
                  placeholder="Header Value"
                  className="flex-1 px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button
                  onClick={() => removeHeader(header.id)}
                  className="px-3 py-2 text-red-600 hover:text-red-800"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          
          <button
            onClick={addHeader}
            className="mt-2 text-sm text-blue-600 hover:text-blue-800"
          >
            + Add Header
          </button>
        </div>
        
        {/* Proxy */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Proxy URL
          </label>
          <input
            type="url"
            value={proxy}
            onChange={(e) => {
              setProxy(e.target.value)
              validateProxy(e.target.value)
            }}
            onBlur={() => validateProxy(proxy)}
            placeholder="http://localhost:8080 or socks5://localhost:1080"
            className={`w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
              proxyError ? 'border-red-500' : ''
            }`}
          />
          {proxyError && (
            <p className="mt-1 text-sm text-red-600">{proxyError}</p>
          )}
          <p className="mt-1 text-sm text-gray-500">
            Optional proxy server for routing traffic (e.g., Burp Suite)
          </p>
        </div>
        
        {/* WAF Bypass Profile */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            WAF Bypass Profile
          </label>
          <select
            value={wafProfile}
            onChange={(e) => setWafProfile(e.target.value)}
            className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {WAF_PROFILES.map(profile => (
              <option key={profile.value} value={profile.value}>
                {profile.label}
              </option>
            ))}
          </select>
          <p className="mt-1 text-sm text-gray-500">
            Pre-configured header sets to bypass common WAFs
          </p>
        </div>
        
        {/* Actions */}
        <div className="flex gap-3 pt-4 border-t">
          <button
            onClick={handleSave}
            disabled={isSaving || !!urlError || !!proxyError}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSaving ? 'Saving...' : 'Save Configuration'}
          </button>
          
          <button
            onClick={() => {
              if (confirm('Reset all fields?')) {
                setUrl('')
                setHeaders([])
                setProxy('')
                setWafProfile('')
                setName('')
                setDescription('')
                setUrlError('')
                setProxyError('')
              }
            }}
            className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
          >
            Reset
          </button>
        </div>
      </div>
    </div>
  )
}
