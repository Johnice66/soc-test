import { useEffect, useState } from 'react'
import { Pencil, Plus, Server, Trash2 } from 'lucide-react'
import { api } from '../api'
import { Modal } from '../components/Modal'
import { PageHeader } from '../components/PageHeader'
import type { Environment, User } from '../types'

const EMPTY = { name: '', base_url: 'http://', timeout_seconds: 10, retries: 2, ssh_host: '', ssh_port: 22, wazuh_api_host: '', wazuh_api_port: 55000, wazuh_indexer_host: '', wazuh_indexer_port: 9200, verify_tls: false, dry_run_default: true, max_parallelism: 1, notes: '' }

export function EnvironmentsPage({ user }: { user: User }) {
  const [items, setItems] = useState<Environment[]>([])
  const [editing, setEditing] = useState<Environment | null | 'new'>(null)
  const [error, setError] = useState('')
  const refresh = () => api<Environment[]>('/api/environments').then(setItems).catch((err) => setError(err.message))
  useEffect(() => { refresh() }, [])
  async function remove(item: Environment) {
    if (!window.confirm(`确认删除环境“${item.name}”？`)) return
    try { await api(`/api/environments/${item.id}`, { method: 'DELETE' }); refresh() } catch (err) { setError(err instanceof Error ? err.message : '删除失败') }
  }
  return <>
    <PageHeader title="环境配置" description="保存目标地址和连接参数，所有敏感凭据在运行时临时输入。" actions={user.role !== 'viewer' ? <button className="primary-button" onClick={() => setEditing('new')}><Plus size={16} />新建环境</button> : null} />
    {error ? <div className="alert error-alert">{error}</div> : null}
    <section className="table-section"><div className="table-scroll"><table><thead><tr><th>环境</th><th>Base URL</th><th>SSH</th><th>Wazuh API</th><th>Indexer</th><th>Dry Run</th><th>更新时间</th><th><span className="sr-only">操作</span></th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><span className="name-cell"><Server size={16} />{item.name}</span></td><td className="mono">{item.base_url}</td><td>{item.ssh_host ? `${item.ssh_host}:${item.ssh_port}` : '未配置'}</td><td>{item.wazuh_api_host ? `${item.wazuh_api_host}:${item.wazuh_api_port}` : '未配置'}</td><td>{item.wazuh_indexer_host ? `${item.wazuh_indexer_host}:${item.wazuh_indexer_port}` : '未配置'}</td><td>{item.dry_run_default ? '开启' : '关闭'}</td><td>{new Date(item.updated_at).toLocaleString()}</td><td><div className="row-actions">{user.role !== 'viewer' ? <button className="icon-button" title="编辑环境" onClick={() => setEditing(item)}><Pencil size={16} /></button> : null}{user.role === 'admin' ? <button className="icon-button danger-icon" title="删除环境" onClick={() => remove(item)}><Trash2 size={16} /></button> : null}</div></td></tr>)}</tbody></table>{items.length === 0 ? <div className="table-empty">尚未配置环境</div> : null}</div></section>
    {editing ? <EnvironmentModal item={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh() }} /> : null}
  </>
}

function EnvironmentModal({ item, onClose, onSaved }: { item: Environment | null; onClose: () => void; onSaved: () => void }) {
  const [value, setValue] = useState(item ? { ...item } : EMPTY)
  const [error, setError] = useState('')
  const set = (key: string, next: string | number | boolean) => setValue((current) => ({ ...current, [key]: next }))
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError('')
    try { await api(item ? `/api/environments/${item.id}` : '/api/environments', { method: item ? 'PUT' : 'POST', body: JSON.stringify(value) }); onSaved() } catch (err) { setError(err instanceof Error ? err.message : '保存失败') }
  }
  return <Modal title={item ? '编辑环境' : '新建环境'} onClose={onClose}><form className="modal-form" onSubmit={submit}>
    <div className="form-grid"><label>环境名称<input value={value.name} onChange={(e) => set('name', e.target.value)} required /></label><label>Base URL<input value={value.base_url} onChange={(e) => set('base_url', e.target.value)} placeholder="http://192.168.1.193:16001" required /></label><label>请求超时（秒）<input type="number" min="1" max="120" value={value.timeout_seconds} onChange={(e) => set('timeout_seconds', Number(e.target.value))} /></label><label>重试次数<input type="number" min="0" max="5" value={value.retries} onChange={(e) => set('retries', Number(e.target.value))} /></label></div>
    <h3>SSH</h3><div className="form-grid"><label>主机<input value={value.ssh_host} onChange={(e) => set('ssh_host', e.target.value)} /></label><label>端口<input type="number" value={value.ssh_port} onChange={(e) => set('ssh_port', Number(e.target.value))} /></label></div>
    <h3>Wazuh</h3><div className="form-grid"><label>API 主机<input value={value.wazuh_api_host} onChange={(e) => set('wazuh_api_host', e.target.value)} /></label><label>API 端口<input type="number" value={value.wazuh_api_port} onChange={(e) => set('wazuh_api_port', Number(e.target.value))} /></label><label>Indexer 主机<input value={value.wazuh_indexer_host} onChange={(e) => set('wazuh_indexer_host', e.target.value)} /></label><label>Indexer 端口<input type="number" value={value.wazuh_indexer_port} onChange={(e) => set('wazuh_indexer_port', Number(e.target.value))} /></label></div>
    <div className="inline-options"><label><input type="checkbox" checked={value.verify_tls} onChange={(e) => set('verify_tls', e.target.checked)} />验证 TLS 证书</label><label><input type="checkbox" checked={value.dry_run_default} onChange={(e) => set('dry_run_default', e.target.checked)} />默认 Dry Run</label></div>
    <label>备注<textarea rows={3} value={value.notes} onChange={(e) => set('notes', e.target.value)} /></label>
    {error ? <div className="form-error">{error}</div> : null}<footer><button type="button" className="secondary-button" onClick={onClose}>取消</button><button className="primary-button">保存环境</button></footer>
  </form></Modal>
}
