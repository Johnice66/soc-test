import { useEffect, useState } from 'react'
import { api } from './api'
import type { User } from './types'
import { AppShell, type Page } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'
import { RunsPage } from './pages/RunsPage'
import { EnvironmentsPage } from './pages/EnvironmentsPage'
import { CasesPage } from './pages/CasesPage'
import { ReportsPage } from './pages/ReportsPage'
import { UsersPage } from './pages/UsersPage'

export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState<Page>('runs')

  useEffect(() => {
    api<User>('/api/auth/me').then(setUser).catch(() => setUser(null)).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="app-loading">正在加载控制台...</div>
  if (!user) return <LoginPage onLogin={setUser} />

  const content = page === 'runs' ? <RunsPage user={user} />
    : page === 'environments' ? <EnvironmentsPage user={user} />
    : page === 'cases' ? <CasesPage />
    : page === 'reports' ? <ReportsPage />
    : <UsersPage />

  return <AppShell user={user} page={page} onPage={setPage} onLogout={() => setUser(null)}>{content}</AppShell>
}
