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
  }, [])

  return (
    <div>
      <div className="card">
        <h2>Welcome to VulnChain</h2>
        <p>Advanced CTF Web Exploitation Framework</p>
        
        {loading ? (
          <div className="spinner"></div>
        ) : health ? (
          <div className="alert success mt-2">
            <strong>✓ System Status:</strong> {health.status} (v{health.version})
          </div>
        ) : (
          <div className="alert error mt-2">
            <strong>✗ Backend Offline:</strong> Cannot connect to API
          </div>
        )}
      </div>

      <div className="grid">
        <div className="card">
          <h3>🎯 Quick Start</h3>
          <ol style={{ paddingLeft: '1.5rem', lineHeight: '1.8' }}>
            <li>Create a workspace for your testing</li>
            <li>Add target URLs to scan</li>
            <li>Select attack modules to run</li>
            <li>View findings and evidence</li>
          </ol>
        </div>

        <div className="card">
          <h3>🔧 Features</h3>
          <ul style={{ paddingLeft: '1.5rem', lineHeight: '1.8' }}>
            <li>Automated reconnaissance</li>
            <li>Injection testing (SQL, XSS, etc.)</li>
            <li>API exploitation</li>
            <li>Real-time fuzzing</li>
            <li>OOB vulnerability detection</li>
          </ul>
        </div>

        <div className="card">
          <h3>📊 System Info</h3>
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
                <td>http://localhost:8000</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="card">
          <h3>📚 Resources</h3>
          <ul style={{ paddingLeft: '1.5rem', lineHeight: '1.8' }}>
            <li><a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer" style={{ color: '#58a6ff' }}>API Documentation</a></li>
            <li><a href="http://localhost:5555" target="_blank" rel="noopener noreferrer" style={{ color: '#58a6ff' }}>Flower Monitor</a></li>
            <li>Quick Reference Guide</li>
            <li>Architecture Documentation</li>
          </ul>
        </div>
      </div>

      <div className="card mt-3">
        <h3>⚠️ Legal Disclaimer</h3>
        <p style={{ color: '#f85149', lineHeight: '1.6' }}>
          This tool is designed exclusively for educational purposes, authorized CTF competitions, 
          legal bug bounty programs, and testing on vulnerable-by-design platforms. 
          <strong> Unauthorized use against systems without explicit permission is illegal and unethical.</strong>
        </p>
      </div>
    </div>
  )
}
