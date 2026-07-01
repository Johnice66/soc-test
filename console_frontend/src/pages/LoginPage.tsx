import { useState } from 'react'
import { LockKeyhole, ShieldCheck } from 'lucide-react'
import { login } from '../api'
import type { User } from '../types'

export function LoginPage({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try { onLogin(await login(username, password)) } catch (err) { setError(err instanceof Error ? err.message : '登录失败') } finally { setBusy(false) }
  }
  return <div className="login-page"><form className="login-panel" onSubmit={submit}>
    <div className="login-brand"><ShieldCheck size={26} /><span>SOC 测试控制台</span></div>
    <h1>登录</h1><p>使用授权的内网测试账号继续。</p>
    <label>用户名<input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required /></label>
    <label>密码<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
    {error ? <div className="form-error">{error}</div> : null}
    <button className="primary-button" disabled={busy}><LockKeyhole size={16} />{busy ? '正在登录...' : '登录'}</button>
  </form></div>
}
