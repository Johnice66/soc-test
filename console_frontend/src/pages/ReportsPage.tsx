import { useEffect, useState } from 'react'
import { Download, Eye, FileText } from 'lucide-react'
import { api } from '../api'
import { Modal } from '../components/Modal'
import { PageHeader } from '../components/PageHeader'
import { Status } from '../components/Status'
import type { Report, Run } from '../types'

export function ReportsPage() {
  const [runs, setRuns] = useState<Run[]>([])
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { api<Run[]>('/api/runs?limit=100').then(setRuns) }, [])
  async function open(run: Run) { try { setReport(await api(`/api/runs/${run.id}/report`)) } catch (err) { setError(err instanceof Error ? err.message : '报告读取失败') } }
  return <><PageHeader title="历史报告" description="报告结果来自证据文件，独立于 pytest 进程退出状态。" />
    {error ? <div className="alert error-alert">{error}</div> : null}
    <section className="table-section"><div className="table-scroll"><table><thead><tr><th>运行 ID</th><th>目标环境</th><th>任务状态</th><th>通过</th><th>警告</th><th>失败</th><th>完成时间</th><th>操作</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id}><td className="mono">{run.id}</td><td>{run.environment_snapshot.name}<small className="subcell">{run.environment_snapshot.base_url}</small></td><td><Status value={run.status} /></td><td className="metric pass">{run.totals?.PASS ?? '—'}</td><td className="metric warn">{run.totals?.WARN ?? '—'}</td><td className="metric fail">{run.totals?.FAIL ?? '—'}</td><td>{run.finished_at ? new Date(run.finished_at).toLocaleString() : '—'}</td><td><div className="row-actions"><button className="icon-button" disabled={!run.totals} title="查看报告" onClick={() => open(run)}><Eye size={16} /></button><a className="icon-button" title="下载证据包" href={`/api/runs/${run.id}/evidence-bundle`}><Download size={16} /></a></div></td></tr>)}</tbody></table>{runs.length === 0 ? <div className="table-empty">暂无历史报告</div> : null}</div></section>
    {report ? <Modal title={`测试报告 · ${report.run_id}`} onClose={() => setReport(null)}><div className="report-detail"><div className="report-summary"><span><strong>目标</strong>{report.target}</span>{['PASS', 'WARN', 'FAIL', 'SKIP'].map((key) => <span key={key} className={`report-total total-${key.toLowerCase()}`}><strong>{key}</strong>{report.totals[key] ?? 0}</span>)}</div><div className="table-scroll"><table><thead><tr><th>用例</th><th>MITRE</th><th>状态</th><th>摘要</th><th>耗时</th></tr></thead><tbody>{report.cases.map((item) => <tr key={item.case_id}><td className="mono strong">{item.case_id}</td><td>{item.mitre}</td><td><Status value={item.status} /></td><td>{item.message}</td><td>{Math.round(item.duration_ms)} ms</td></tr>)}</tbody></table></div><footer><a className="secondary-button" href={`/api/runs/${report.run_id}/report?format=markdown`}><FileText size={15} />下载 Markdown</a><a className="primary-button" href={`/api/runs/${report.run_id}/evidence-bundle`}><Download size={15} />下载证据包</a></footer></div></Modal> : null}
  </>
}
