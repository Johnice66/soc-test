import { useEffect, useState } from 'react'
import { Plus, UserRound } from 'lucide-react'
import { api } from '../api'
import { Modal } from '../components/Modal'
import { PageHeader } from '../components/PageHeader'
import type { User } from '../types'

export function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [creating, setCreating] = useState(false)
  const refresh = () => api<User[]>('/api/users').then(setUsers)
  useEffect(() => { refresh() }, [])
  async function toggle(user: User) { await api(`/api/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ active: !user.active }) }); refresh() }
  return <><PageHeader title="用户管理" description="本地账号按管理员、操作员和只读者分配权限。" actions={<button className="primary-button" onClick={() => setCreating(true)}><Plus size={16} />新建用户</button>} />
    <section className="table-section"><div className="table-scroll"><table><thead><tr><th>用户</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>{users.map((user) => <tr key={user.id}><td><span className="name-cell"><UserRound size={16} />{user.username}</span></td><td>{user.role}</td><td>{user.active ? '启用' : '停用'}</td><td>{new Date(user.created_at).toLocaleString()}</td><td><button className="text-button" onClick={() => toggle(user)}>{user.active ? '停用' : '启用'}</button></td></tr>)}</tbody></table></div></section>
    {creating ? <CreateUser onClose={() => setCreating(false)} onSaved={() => { setCreating(false); refresh() }} /> : null}
  </>
}

function CreateUser({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [role, setRole] = useState('operator'); const [error, setError] = useState('')
  async function submit(event: React.FormEvent) { event.preventDefault(); try { await api('/api/users', { method: 'POST', body: JSON.stringify({ username, password, role }) }); onSaved() } catch (err) { setError(err instanceof Error ? err.message : '创建失败') } }
  return <Modal title="新建用户" onClose={onClose}><form className="modal-form" onSubmit={submit}><label>用户名<input autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} required /></label><label>初始密码<input type="password" autoComplete="new-password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required /></label><label>角色<select value={role} onChange={(e) => setRole(e.target.value)}><option value="operator">操作员</option><option value="viewer">只读者</option><option value="admin">管理员</option></select></label>{error ? <div className="form-error">{error}</div> : null}<footer><button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button">创建用户</button></footer></form></Modal>
}
