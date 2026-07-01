import { useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { api } from '../api'
import { PageHeader } from '../components/PageHeader'
import type { TestCase } from '../types'

export function CasesPage() {
  const [items, setItems] = useState<TestCase[]>([])
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('all')
  useEffect(() => { api<TestCase[]>('/api/test-cases').then(setItems) }, [])
  const categories = useMemo(() => [...new Set(items.map((item) => item.category))].sort(), [items])
  const filtered = useMemo(() => items.filter((item) => (category === 'all' || item.category === category) && `${item.case_id} ${item.test_name} ${item.markers.join(' ')}`.toLowerCase().includes(query.toLowerCase())), [items, query, category])
  return <><PageHeader title="测试用例" description="查看控制台可执行的 pytest 用例、标记和前置条件。" />
    <div className="filter-bar"><label className="search-field"><Search size={16} /><input placeholder="搜索用例 ID 或标记" value={query} onChange={(e) => setQuery(e.target.value)} /></label><select value={category} onChange={(e) => setCategory(e.target.value)}><option value="all">全部分类</option>{categories.map((item) => <option key={item}>{item}</option>)}</select><span>{filtered.length} 条</span></div>
    <section className="table-section"><div className="table-scroll"><table><thead><tr><th>用例 ID</th><th>测试函数</th><th>分类</th><th>优先级</th><th>前置条件</th><th>状态</th></tr></thead><tbody>{filtered.map((item) => <tr key={`${item.case_id}-${item.nodeid}`}><td className="mono strong">{item.case_id}</td><td>{item.test_name}</td><td>{item.category}</td><td>{item.markers.find((marker) => /^p\d$/.test(marker)) ?? '—'}</td><td>{item.markers.includes('needs_ssh') || item.markers.includes('needs_wazuh') ? [item.markers.includes('needs_ssh') ? 'SSH' : '', item.markers.includes('needs_wazuh') ? 'Wazuh' : ''].filter(Boolean).join(' + ') : 'HTTP'}</td><td>{item.deferred ? <span className="status status-warn">条件不足</span> : <span className="status status-pass">可执行</span>}</td></tr>)}</tbody></table></div></section>
  </>
}
