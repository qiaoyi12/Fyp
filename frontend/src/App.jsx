import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import AlertFeed from './pages/AlertFeed.jsx'
import ThreatDetail from './pages/ThreatDetail.jsx'
import LogViewer from './pages/LogViewer.jsx'
import Upload from './pages/Upload.jsx'
import ModelMetrics from './pages/ModelMetrics.jsx'

function ProtectedRoute({ children, adminOnly = false, user }) {
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && user.role !== 'admin') return <Navigate to="/dashboard" replace />
  return children
}

export default function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/auth/me')
      .then(r => r.json())
      .then(data => {
        if (data.user) setUser(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  if (loading) return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100vh',background:'#070B14',color:'#2A4A6A',fontFamily:'JetBrains Mono',fontSize:'11px',letterSpacing:'2px'}}>
      LOADING...
    </div>
  )

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login setUser={setUser} />} />
        <Route path="/dashboard" element={
          <ProtectedRoute user={user}>
            <Dashboard user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="/alerts" element={
          <ProtectedRoute user={user}>
            <AlertFeed user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="/alerts/:id" element={
          <ProtectedRoute user={user}>
            <ThreatDetail user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="/logs" element={
          <ProtectedRoute user={user}>
            <LogViewer user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="/upload" element={
          <ProtectedRoute user={user} adminOnly={true}>
            <Upload user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="/metrics" element={
          <ProtectedRoute user={user} adminOnly={true}>
            <ModelMetrics user={user} setUser={setUser} />
          </ProtectedRoute>
        }/>
        <Route path="*" element={<Navigate to={user ? "/dashboard" : "/login"} replace />} />
      </Routes>
    </BrowserRouter>
  )
}