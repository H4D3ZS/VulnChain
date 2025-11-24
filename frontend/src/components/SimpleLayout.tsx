import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'

interface SimpleLayoutProps {
  children: ReactNode
}

export default function SimpleLayout({ children }: SimpleLayoutProps) {
  const location = useLocation()
  
  const navItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/workspaces', label: 'Workspaces', icon: '📁' },
    { path: '/targets', label: 'Targets', icon: '🎯' },
    { path: '/modules', label: 'Modules', icon: '⚔️' },
    { path: '/findings', label: 'Findings', icon: '🔍' },
    { path: '/fuzzing', label: 'Fuzzing', icon: '🔄' },
    { path: '/jwt', label: 'JWT', icon: '🔐' },
    { path: '/oob', label: 'OOB', icon: '📡' },
    { path: '/logs', label: 'Logs', icon: '📋' },
  ]
  
  return (
    <div className="layout">
      <div className="sidebar">
        <h1>VulnChain</h1>
        <p style={{ fontSize: '0.8rem', color: '#8b949e', marginBottom: '2rem' }}>
          CTF Framework
        </p>
        
        <nav className="nav-menu">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={location.pathname === item.path ? 'active' : ''}
            >
              <span style={{ marginRight: '0.5rem' }}>{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>
        
        <div style={{ marginTop: 'auto', paddingTop: '2rem', borderTop: '1px solid #30363d' }}>
          <div style={{ fontSize: '0.75rem', color: '#8b949e' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span>Version</span>
              <span>1.0.0</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Status</span>
              <span style={{ color: '#3fb950' }}>● Online</span>
            </div>
          </div>
        </div>
      </div>
      
      <div className="main-content">
        {children}
      </div>
    </div>
  )
}
