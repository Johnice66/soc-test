import { CircleAlert, CircleCheck, CircleDashed, CircleX, LoaderCircle } from 'lucide-react'

export function Status({ value }: { value: string }) {
  const Icon = value === 'completed' || value === 'PASS' ? CircleCheck
    : value === 'failed' || value === 'FAIL' ? CircleX
    : value === 'running' ? LoaderCircle
    : value === 'WARN' ? CircleAlert : CircleDashed
  const labels: Record<string, string> = { queued: '排队中', running: '运行中', completed: '已完成', failed: '执行失败', cancelled: '已取消' }
  return <span className={`status status-${value.toLowerCase()}`}><Icon size={14} />{labels[value] ?? value}</span>
}
