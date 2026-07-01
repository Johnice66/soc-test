import { useEffect, useMemo, useState } from 'react'
import { Activity, Eye, FlaskConical, KeyRound, Play, RefreshCw, Square, Wifi } from 'lucide-react'
import { api } from '../api'
import { PageHeader } from '../components/PageHeader'
import { Status } from '../components/Status'
import type { Environment, Run, TestCase, User } from '../types'

const PRESETS = [
  { id: 'http_only', name: 'HTTP 快速回归', note: '无需 SSH / Wazuh' },
  { id: 'p0', name: 'P0 核心用例', note: '核心与流水线用例' },
  { id: 'pipeline', name: '端到端流水线', note: '六步链路冒烟' },
  { id: 'custom', name: '自定义用例', note: '按用例 ID 选择' },
]

const EMPTY_SECRETS = {
  platform: { username: '', password: '', cookie: '', bearer: '' },
  ssh: { username: '', password: '', private_key: '', victim_account: 'testuser', attacker_source_ip: '' },
  wazuh_api: { username: '', password: '' },
  wazuh_indexer: { username: '', password: '' },
}

export function RunsPage({ user }: { user: User }) {
  const [environments, setEnvironments] = useState<Environment[]>([])
  const [runs, setRuns] = useState<Run[]>([])
  const [cases, setCases] = useState<TestCase[]>([])
  const [environmentId, setEnvironmentId] = useState(0)
  const [preset, setPreset] = useState('http_only')
  const [selectedCases, setSelectedCases] = useState<string[]>([])
  const [infrastructure, setInfrastructure] = useState(false)
  const [destructive, setDestructive] = useState(false)
  const [dryRun, setDryRun] = useState(true)
  const [confirmation, setConfirmation] = useState('')
  const [secrets, setSecrets] = useState(EMPTY_SECRETS)
  const [showSecrets, setShowSecrets] = useState(false)
  const [probe, setProbe] = useState<Record<string, { ok: boolean }> | null>(null)
  const [activeRun, setActiveRun] = useState<Run | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    const [envData, runData, caseData] = await Promise.all([
      api<Environment[]>('/api/environments'), api<Run[]>('/api/runs?limit=20'), api<TestCase[]>('/api/test-cases'),
    ])
    setEnvironments(envData); setRuns(runData); setCases(caseData)
    setEnvironmentId((current) => current || envData[0]?.id || 0)
    setActiveRun((current) => current ? runData.find((run) => run.id === current.id) ?? current : runData.find((run) => run.status === 'running' || run.status === 'queued') ?? null)
  }

  useEffect(() => { refresh().catch((err) => setError(err.message)) }, [])
  useEffect(() => {
    if (!activeRun || !['queued', 'running'].includes(activeRun.status)) return
    const events = new EventSource(`/api/runs/${activeRun.id}/events`)
    events.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'log') setLogs((current) => [...current.slice(-199), data.line])
      if (data.type === 'status') {
        setActiveRun((current) => current ? { ...current, status: data.status, totals: data.totals ? JSON.parse(data.totals) : current.totals, error: data.error ?? '' } : current)
        if (['completed', 'failed', 'cancelled'].includes(data.status)) {
          events.close(); refresh().catch(() => undefined)
        }
      }
    }
    return () => events.close()
  }, [activeRun?.id, activeRun?.status])

  const selectedEnvironment = environments.find((environment) => environment.id === environmentId)
  const customCases = useMemo(() => cases.filter((item) => !item.deferred), [cases])
  const canRun = user.role !== 'viewer' && Boolean(selectedEnvironment)

  async function probeEnvironment() {
    if (!environmentId) return
    setBusy(true); setError('')
    try { setProbe(await api(`/api/environments/${environmentId}/probe`, { method: 'POST' })) } catch (err) { setError(err instanceof Error ? err.message : '连接检测失败') } finally { setBusy(false) }
  }

  async function startRun() {
    setBusy(true); setError(''); setLogs([])
    try {
      const run = await api<Run>('/api/runs', { method: 'POST', body: JSON.stringify({
        environment_id: environmentId, preset, case_ids: selectedCases,
        include_infrastructure: infrastructure, include_destructive: destructive,
        dry_run: dryRun, confirmation, credentials: secrets,
      }) })
      setSecrets(EMPTY_SECRETS); setShowSecrets(false); setActiveRun(run); await refresh()
    } catch (err) { setError(err instanceof Error ? err.message : '启动失败') } finally { setBusy(false) }
  }

  async function cancelRun() {
    if (!activeRun) return
    await api(`/api/runs/${activeRun.id}/cancel`, { method: 'POST' })
    await refresh()
  }

  return <>
    <PageHeader title="新建测试运行" description="选择目标环境和测试范围，凭据仅用于本次任务。" actions={<button className="secondary-button" onClick={() => refresh()}><RefreshCw size={15} />刷新</button>} />
    {error ? <div className="alert error-alert">{error}</div> : null}
    <div className="run-layout">
      <section className="work-panel run-config">
        <div className="section-heading"><div><h2>目标环境</h2><p>测试从控制台所在网络发起。</p></div><button className="secondary-button" disabled={!canRun || busy} onClick={probeEnvironment}><Wifi size={15} />检测连接</button></div>
        <label className="field">环境<select value={environmentId} onChange={(e) => { setEnvironmentId(Number(e.target.value)); setProbe(null) }}><option value={0}>请选择环境</option>{environments.map((environment) => <option key={environment.id} value={environment.id}>{environment.name} · {environment.base_url}</option>)}</select></label>
        {selectedEnvironment ? <div className="environment-strip"><span><strong>Base URL</strong>{selectedEnvironment.base_url}</span><span><strong>SSH</strong>{selectedEnvironment.ssh_host || '未配置'}</span><span><strong>Wazuh API</strong>{selectedEnvironment.wazuh_api_host || '未配置'}</span></div> : <div className="empty-inline">尚未创建环境，请先前往“环境配置”。</div>}
        {probe ? <div className="probe-row">{Object.entries(probe).map(([name, value]) => <span key={name} className={value.ok ? 'probe-ok' : 'probe-fail'}>{name} · {value.ok ? '可达' : '不可达'}</span>)}</div> : null}

        <div className="section-heading section-divider"><div><h2>测试范围</h2><p>服务端只接受以下预设和已发现用例。</p></div></div>
        <div className="preset-grid">{PRESETS.map((item) => <button key={item.id} className={preset === item.id ? 'preset selected' : 'preset'} onClick={() => setPreset(item.id)}><span>{item.name}</span><small>{item.note}</small></button>)}</div>
        {preset === 'custom' ? <div className="case-picker">{customCases.map((item) => <label key={item.case_id}><input type="checkbox" checked={selectedCases.includes(item.case_id)} onChange={(e) => setSelectedCases((current) => e.target.checked ? [...current, item.case_id] : current.filter((id) => id !== item.case_id))} /><span>{item.case_id}</span><small>{item.category}</small></label>)}</div> : null}

        <div className="options-list">
          <label><input type="checkbox" checked={infrastructure} onChange={(e) => { setInfrastructure(e.target.checked); setShowSecrets(e.target.checked || showSecrets) }} /><span><strong>SSH / Wazuh</strong><small>启用需要基础设施凭据的用例</small></span></label>
          <label><input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /><span><strong>Dry Run</strong><small>不执行真实响应动作</small></span></label>
          <label className="danger-option"><input type="checkbox" disabled={user.role !== 'admin'} checked={destructive} onChange={(e) => { setDestructive(e.target.checked); if (e.target.checked) setDryRun(false) }} /><span><strong>破坏性用例</strong><small>仅管理员可启用，可能修改目标环境</small></span></label>
        </div>
        <button className="text-button" onClick={() => setShowSecrets(!showSecrets)}><KeyRound size={15} />{showSecrets ? '收起临时凭据' : '输入本次临时凭据'}</button>
        {showSecrets ? <SecretFields secrets={secrets} onChange={setSecrets} infrastructure={infrastructure} /> : null}
        {destructive && selectedEnvironment ? <label className="field danger-confirm">输入环境名称“{selectedEnvironment.name}”确认<input value={confirmation} onChange={(e) => setConfirmation(e.target.value)} autoComplete="off" /></label> : null}
        <div className="run-actions"><span>同一时间仅执行一个任务，其余任务自动排队。</span><button className="primary-button" disabled={!canRun || busy || preset === 'custom' && !selectedCases.length} onClick={startRun}><Play size={16} />{busy ? '正在提交...' : '开始测试'}</button></div>
      </section>

      <aside className="work-panel live-panel">
        <div className="section-heading"><div><h2>当前运行</h2><p>{activeRun?.id ?? '暂无活动任务'}</p></div>{activeRun ? <Status value={activeRun.status} /> : null}</div>
        {activeRun ? <>
          <div className="run-summary"><span><strong>环境</strong>{activeRun.environment_snapshot.name}</span><span><strong>范围</strong>{PRESETS.find((item) => item.id === activeRun.preset)?.name}</span></div>
          <div className="log-view" aria-live="polite">{logs.length ? logs.map((line, index) => <div key={`${index}-${line}`}>{line}</div>) : <div className="log-placeholder"><Activity size={20} />等待运行日志...</div>}</div>
          {['queued', 'running'].includes(activeRun.status) && user.role !== 'viewer' ? <button className="danger-button full-button" onClick={cancelRun}><Square size={14} />停止运行</button> : null}
        </> : <div className="empty-state"><FlaskConical size={28} /><strong>等待新任务</strong><span>开始测试后，运行日志会显示在这里。</span></div>}
      </aside>
    </div>
    <section className="table-section"><div className="section-heading"><div><h2>最近运行</h2><p>任务状态与用例结果分别记录。</p></div></div><RunTable runs={runs} onSelect={(run) => { setActiveRun(run); setLogs([]) }} /></section>
  </>
}

function SecretFields({ secrets, onChange, infrastructure }: { secrets: typeof EMPTY_SECRETS; onChange: (value: typeof EMPTY_SECRETS) => void; infrastructure: boolean }) {
  function update(group: keyof typeof EMPTY_SECRETS, key: string, value: string) { onChange({ ...secrets, [group]: { ...secrets[group], [key]: value } }) }
  return <div className="secret-fields">
    <h3>平台身份（可选）</h3><div className="form-grid"><label>用户名<input autoComplete="off" value={secrets.platform.username} onChange={(e) => update('platform', 'username', e.target.value)} /></label><label>密码<input type="password" autoComplete="new-password" value={secrets.platform.password} onChange={(e) => update('platform', 'password', e.target.value)} /></label><label>Bearer Token<input type="password" autoComplete="new-password" value={secrets.platform.bearer} onChange={(e) => update('platform', 'bearer', e.target.value)} /></label><label>Cookie<input type="password" autoComplete="new-password" value={secrets.platform.cookie} onChange={(e) => update('platform', 'cookie', e.target.value)} /></label></div>
    {infrastructure ? <><h3>基础设施身份</h3><div className="form-grid"><label>SSH 用户名<input autoComplete="off" value={secrets.ssh.username} onChange={(e) => update('ssh', 'username', e.target.value)} /></label><label>SSH 密码<input type="password" autoComplete="new-password" value={secrets.ssh.password} onChange={(e) => update('ssh', 'password', e.target.value)} /></label><label>Wazuh API 用户名<input autoComplete="off" value={secrets.wazuh_api.username} onChange={(e) => update('wazuh_api', 'username', e.target.value)} /></label><label>Wazuh API 密码<input type="password" autoComplete="new-password" value={secrets.wazuh_api.password} onChange={(e) => update('wazuh_api', 'password', e.target.value)} /></label><label>Indexer 用户名<input autoComplete="off" value={secrets.wazuh_indexer.username} onChange={(e) => update('wazuh_indexer', 'username', e.target.value)} /></label><label>Indexer 密码<input type="password" autoComplete="new-password" value={secrets.wazuh_indexer.password} onChange={(e) => update('wazuh_indexer', 'password', e.target.value)} /></label></div></> : null}
    <p className="secret-note">这些值不会保存到环境、数据库或报告中，任务结束后自动销毁。</p>
  </div>
}

function RunTable({ runs, onSelect }: { runs: Run[]; onSelect: (run: Run) => void }) {
  return <div className="table-scroll"><table><thead><tr><th>运行 ID</th><th>环境</th><th>范围</th><th>状态</th><th>通过</th><th>警告</th><th>失败</th><th>创建时间</th><th><span className="sr-only">操作</span></th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td className="mono">{run.id}</td><td>{run.environment_snapshot.name}</td><td>{PRESETS.find((item) => item.id === run.preset)?.name}</td><td><Status value={run.status} /></td><td className="metric pass">{run.totals?.PASS ?? '—'}</td><td className="metric warn">{run.totals?.WARN ?? '—'}</td><td className="metric fail">{run.totals?.FAIL ?? '—'}</td><td>{new Date(run.created_at).toLocaleString()}</td><td><button className="icon-button" title="查看运行" onClick={() => onSelect(run)}><Eye size={16} /></button></td></tr>)}</tbody></table>{runs.length === 0 ? <div className="table-empty">暂无运行记录</div> : null}</div>
}
