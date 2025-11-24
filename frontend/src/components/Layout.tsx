/**
 * Main Application Layout
 * 
 * Complete application shell with:
 * - Navigation sidebar with module categories
 * - Header with workspace selector and settings
 * - Route integration for different views
 * - Responsive design
 */

import { useState, ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'

interface LayoutProps {
  children: ReactNode
  currentView?: string
  onViewChange?: (view: string) => void
  currentWorkspace?: string
  workspaces?: Array<{ id: string; name: string }>
  onWorkspaceChange?: (workspaceId: string) => void
}

interface NavItem {
  id: string
  label: string
  icon: string
  category?: string
}

export default function Layout({
  children,
  currentView = 'dashboard',
  onViewChange,
  currentWorkspace,
  workspaces = [],
  onWorkspaceChange
}: LayoutProps) {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [showWorkspaceMenu, setShowWorkspaceMenu] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  
  const navItems: NavItem[] = [
    { id: '/', label: 'Dashboard', icon: '📊' },
    { id: '/targets', label: 'Target Config', icon: '🎯' },
    { id: '/modules', label: 'Attack Modules', icon: '⚔️' },
    { id: '/fuzzing', label: 'Fuzzing Monitor', icon: '🔄' },
    { id: '/findings', label: 'Findings', icon: '🔍' },
    { id: '/logs', label: 'Logs', icon: '📋' },
    { id: '/oob', label: 'OOB Listener', icon: '📡' },
    { id: '/jwt', label: 'JWT Inspector', icon: '🔐' },
    { id: '/workspaces', label: 'Workspaces', icon: '📁' },
  ]
  
  const categories = [
    {
      name: 'Overview',
      items: ['/', '/targets']
    },
    {
      name: 'Testing',
      items: ['/modules', '/fuzzing']
    },
    {
      name: 'Analysis',
      items: ['/findings', '/logs', '/oob', '/jwt']
    },
    {
      name: 'Management',
      items: ['/workspaces']
    }
  ]
  
  const currentWorkspaceName = workspaces.find(w => w.id === currentWorkspace)?.name || 'No Workspace'
  
  return (
    <div className="layout">
      {/* Header */}
      <header className="header">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 hover:bg-gray-100 rounded-lg lg:hidden"
          >
            ☰
          </button>
          
          <div className="flex items-center gap-3">
            <div className="text-2xl">🛡️</div>
            <div>
              <h1 className="text-xl font-bold text-gray-900">VulnChain</h1>
              <p className="text-xs text-gray-500">CTF Framework</p>
            </div>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Workspace Selector */}
          <div className="relative">
            <button
              onClick={() => setShowWorkspaceMenu(!showWorkspaceMenu)}
              className="flex items-center gap-2 px-4 py-2 bg-gray-100 rounded-lg hover:bg-gray-200"
            >
              <span className="text-sm">📁</span>
              <span className="text-sm font-medium">{currentWorkspaceName}</span>
              <span className="text-xs">▼</span>
            </button>
            
            {showWorkspaceMenu && (
              <div className="absolute right-0 mt-2 w-64 bg-white rounded-lg shadow-lg border py-2 z-20">
                <div className="px-4 py-2 text-xs font-medium text-gray-500 uppercase">
                  Workspaces
                </div>
                {workspaces.map(workspace => (
                  <button
                    key={workspace.id}
                    onClick={() => {
                      onWorkspaceChange?.(workspace.id)
                      setShowWorkspaceMenu(false)
                    }}
                    className={`w-full text-left px-4 py-2 hover:bg-gray-50 ${
                      workspace.id === currentWorkspace ? 'bg-blue-50 text-blue-700' : ''
                    }`}
                  >
                    <div className="text-sm font-medium">{workspace.name}</div>
                  </button>
                ))}
                <div className="border-t mt-2 pt-2">
                  <Link
                    to="/workspaces"
                    onClick={() => setShowWorkspaceMenu(false)}
                    className="block w-full text-left px-4 py-2 text-sm text-blue-600 hover:bg-gray-50"
                  >
                    + Manage Workspaces
                  </Link>
                </div>
              </div>
            )}
          </div>
          
          {/* Notifications */}
          <button className="relative p-2 hover:bg-gray-100 rounded-lg">
            <span className="text-xl">🔔</span>
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>
          
          {/* User Menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2 p-2 hover:bg-gray-100 rounded-lg"
            >
              <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                U
              </div>
            </button>
            
            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border py-2 z-20">
                <button className="w-full text-left px-4 py-2 text-sm hover:bg-gray-50">
                  ⚙️ Settings
                </button>
                <button className="w-full text-left px-4 py-2 text-sm hover:bg-gray-50">
                  📚 Documentation
                </button>
                <button className="w-full text-left px-4 py-2 text-sm hover:bg-gray-50">
                  ℹ️ About
                </button>
                <div className="border-t my-2"></div>
                <button className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-50">
                  🚪 Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </header>
      
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <aside
          className={`bg-white border-r w-64 flex-shrink-0 overflow-y-auto transition-all ${
            sidebarOpen ? '' : '-ml-64 lg:ml-0'
          }`}
        >
          <nav className="p-4 space-y-6">
            {categories.map((category) => (
              <div key={category.name}>
                <div className="text-xs font-semibold text-gray-500 uppercase mb-2 px-3">
                  {category.name}
                </div>
                <div className="space-y-1">
                  {category.items.map((itemId) => {
                    const item = navItems.find(n => n.id === itemId)
                    if (!item) return null
                    
                    const isActive = location.pathname === item.id
                    
                    return (
                      <Link
                        key={item.id}
                        to={item.id}
                        className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                          isActive
                            ? 'bg-blue-50 text-blue-700 font-medium'
                            : 'text-gray-700 hover:bg-gray-50'
                        }`}
                      >
                        <span className="text-lg">{item.icon}</span>
                        <span>{item.label}</span>
                      </Link>
                    )
                  })}
                </div>
              </div>
            ))}
          </nav>
          
          {/* Sidebar Footer */}
          <div className="p-4 border-t mt-auto">
            <div className="text-xs text-gray-500 space-y-1">
              <div className="flex items-center justify-between">
                <span>Version</span>
                <span className="font-medium">1.0.0-beta</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Status</span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  <span className="font-medium text-green-600">Online</span>
                </span>
              </div>
            </div>
          </div>
        </aside>
        
        {/* Main Content */}
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
      
      {/* Mobile Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-10 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  )
}
