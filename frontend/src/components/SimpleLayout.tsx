import { ReactNode, useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'

interface SimpleLayoutProps {
  children: ReactNode
}

export default function SimpleLayout({ children }: SimpleLayoutProps) {
  const location = useLocation()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
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
  
  // Close mobile menu when route changes
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [location.pathname])
  
  // Close mobile menu on escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsMobileMenuOpen(false)
      }
    }
    
    if (isMobileMenuOpen) {
      document.addEventListener('keydown', handleEscape)
      // Prevent body scroll when menu is open
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }
    
    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = 'unset'
    }
  }, [isMobileMenuOpen])
  
  return (
    <div className="layout">
      {/* Mobile Menu Toggle */}
      <button
        className="mobile-menu-toggle"
        onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        aria-label="Toggle menu"
        aria-expanded={isMobileMenuOpen}
      >
        {isMobileMenuOpen ? '✕' : '☰'}
      </button>
      
      {/* Overlay for mobile menu */}
      <div
        className={`sidebar-overlay ${isMobileMenuOpen ? 'active' : ''}`}
        onClick={() => setIsMobileMenuOpen(false)}
        aria-hidden="true"
      />
      
      {/* Sidebar */}
      <div className={`sidebar ${isMobileMenuOpen ? 'active' : ''}`}>
        <div>
          <h1>VulnChain</h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '2rem' }}>
            CTF Framework
          </p>
        </div>
        
        <nav className="nav-menu">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={location.pathname === item.path ? 'active' : ''}
              onClick={() => setIsMobileMenuOpen(false)}
            >
              <span style={{ marginRight: '0.5rem' }}>{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>
        
        <div style={{ 
          marginTop: 'auto', 
          paddingTop: '2rem', 
          borderTop: '1px solid var(--border-primary)' 
        }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              marginBottom: '0.5rem' 
            }}>
              <span>Version</span>
              <span>1.0.0</span>
            </div>
            <div style={{ 
              display: 'flex', 
              justifyContent: 'space-between', 
              alignItems: 'center' 
            }}>
              <span>Status</span>
              <span style={{ color: 'var(--success)' }}>● Online</span>
            </div>
          </div>
        </div>
      </div>
      
      {/* Main Content */}
      <div className="main-content">
        {children}
      </div>
    </div>
  )
}
