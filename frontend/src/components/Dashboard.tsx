import { useEffect, useState } from 'react'
import { healthCheck } from '../services/api'

export default function Dashboard() {
  const [health, setHealth] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await healthCheck()
        setHealth(response.data)
      } catch (error) {
        console.error('Health check failed:', error)
      } finally {
        setLoading(false)
      }
    }
    checkHealth()

    // Poll health status every 30 seconds
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div>
      <div className="card">
        <h2>Welcome to VulnChain</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
          Advanced CTF Web Exploitation Framework
        </p>

        {loading ? (
          <div className="spinner"></div>
        ) : health ? (
          <div className="alert success mt-2">
            <strong>✓ System Status:</strong> {health.status} (v{health.version})
          </div>
        ) : (
          <div className="alert error mt-2">
            <strong>✗ Backend Offline:</strong> Cannot connect to API. Please ensure the backend is running.
          </div>
        )}
      </div>

      <div className="grid">
        <div className="card">
          <h3>🎯 Quick Start</h3>
          <ol style={{ paddingLeft: '1.5rem', lineHeight: '1.8', color: 'var(--text-secondary)' }}>
            <li>Create a workspace for your testing</li>
            <li>Add target URLs to scan</li>
            <li>Select attack modules to run</li>
            <li>View findings and evidence</li>
          </ol>
        </div>

        <div className="card">
          <h3>🔧 Features</h3>
          <ul style={{ paddingLeft: '1.5rem', lineHeight: '1.8', color: 'var(--text-secondary)' }}>
            <li>25+ Attack Modules</li>
            <li>Automated Reconnaissance</li>
            <li>Injection Testing (SQL, XSS, etc.)</li>
            <li>API Exploitation</li>
            <li>Real-time Fuzzing</li>
            <li>OOB Vulnerability Detection</li>
          </ul>
        </div>

        <div className="card">
          <h3>📊 System Info</h3>
          <div className="table-container">
            <table>
              <tbody>
                <tr>
                  <td><strong>Backend:</strong></td>
                  <td>
                    {health ? (
                      <span className="badge success">Online</span>
                    ) : (
                      <span className="badge danger">Offline</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td><strong>Version:</strong></td>
                  <td>{health?.version || 'N/A'}</td>
                </tr>
                <tr>
                  <td><strong>API:</strong></td>
                  <td style={{ fontSize: '0.85rem' }}>http://localhost:8000</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <h3>📚 Resources</h3>
          <ul style={{ paddingLeft: '1.5rem', lineHeight: '1.8' }}>
            <li>
              <a
                href="http://localhost:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--accent-primary)', textDecoration: 'none' }}
              >
                API Documentation →
              </a>
            </li>
            <li>
              <a
                href="http://localhost:5555"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--accent-primary)', textDecoration: 'none' }}
              >
                Flower Monitor →
              </a>
            </li>
            <li style={{ color: 'var(--text-secondary)' }}>Quick Reference Guide</li>
            <li style={{ color: 'var(--text-secondary)' }}>Architecture Documentation</li>
          </ul>
        </div>
      </div>

      <div className="card mt-3">
        <h3>⚠️ Legal Disclaimer</h3>
        <p style={{ color: 'var(--danger-hover)', lineHeight: '1.6' }}>
          This tool is designed exclusively for educational purposes, authorized CTF competitions,
          legal bug bounty programs, and testing on vulnerable-by-design platforms.
          <strong> Unauthorized use against systems without explicit permission is illegal and unethical.</strong>
        </p>
      </div>

      <div className="grid" style={{ marginTop: 'var(--spacing-lg)' }}>
        <div className="card">
          <h3>🚀 Getting Started</h3>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>
            New to VulnChain? Start by creating your first workspace and adding a target.
          </p>
          <div style={{ display: 'flex', gap: 'var(--spacing-sm)', flexWrap: 'wrap' }}>
            <button onClick={() => window.location.href = '/workspaces'}>
              Create Workspace
            </button>
            <button className="secondary" onClick={() => window.location.href = '/targets'}>
              Add Target
            </button>
          </div>
        </div>

        <div className="card">
          <h3>📈 Statistics</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 'var(--spacing-md)' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 'var(--font-size-2xl)', color: 'var(--accent-primary)', fontWeight: 'bold' }}>
                25+
              </div>
              <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                Attack Modules
              </div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 'var(--font-size-2xl)', color: 'var(--success)', fontWeight: 'bold' }}>
                {health ? '100%' : '0%'}
              </div>
              <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--text-secondary)' }}>
                System Uptime
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
