import type { ReactNode } from 'react'
import { ClipboardCheck, FileClock, FlaskConical, LogOut, ServerCog, ShieldCheck, Users } from 'lucide-react'
import { api, clearCsrf } from '../api'
import type { User } from '../types'

export type Page = 'runs' | 'environments' | 'cases' | 'reports' | 'users'

const NAV = [
  { id: 'runs' as const, label: '测试运行', icon: FlaskConical },
  { id: 'environments' as const, label: '环境配置', icon: ServerCog },
  { id: 'cases' as const, label: '测试用例', icon: ClipboardCheck },
  { id: 'reports' as const, label: '历史报告', icon: FileClock },
]

export function AppShell({ user, page, onPage, onLogout, children }: {
  user: User; page: Page; onPage: (page: Page) => void; onLogout: () => void; children: ReactNode
}) {
  const items = user.role === 'admin' ? [...NAV, { id: 'users' as const, label: '用户管理', icon: Users }] : NAV
  async function logout() {
    await api('/api/auth/logout', { method: 'POST' }).catch(() => undefined)
    clearCsrf()
    onLogout()
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><ShieldCheck size={20} /></span><span>SOC 测试控制台</span></div>
      <nav>{items.map(({ id, label, icon: Icon }) => <button key={id} className={page === id ? 'active' : ''} onClick={() => onPage(id)}><Icon size={17} /><span>{label}</span></button>)}</nav>
      <div className="account"><div><strong>{user.username}</strong><span>{user.role}</span></div><button className="icon-button" title="退出登录" onClick={logout}><LogOut size={17} /></button></div>
    </aside>
    <main className="main-content">{children}</main>
  </div>
}
