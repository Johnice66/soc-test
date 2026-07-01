export type Role = 'admin' | 'operator' | 'viewer'

export interface User {
  id: number
  username: string
  role: Role
  active: boolean
  created_at: string
}

export interface Environment {
  id: number
  name: string
  base_url: string
  timeout_seconds: number
  retries: number
  ssh_host: string
  ssh_port: number
  wazuh_api_host: string
  wazuh_api_port: number
  wazuh_indexer_host: string
  wazuh_indexer_port: number
  verify_tls: boolean
  dry_run_default: boolean
  max_parallelism: number
  notes: string
  created_at: string
  updated_at: string
}

export interface TestCase {
  case_id: string
  nodeid: string
  test_name: string
  markers: string[]
  category: string
  deferred: boolean
}

export interface Run {
  id: string
  environment_id: number
  environment_snapshot: Environment
  preset: 'http_only' | 'p0' | 'pipeline' | 'custom'
  case_ids: string[]
  include_infrastructure: boolean
  include_destructive: boolean
  dry_run: boolean
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  requested_by: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  exit_code: number | null
  totals: Record<string, number> | null
  error: string
}

export interface Report {
  run_id: string
  target: string
  generated_at: string
  totals: Record<string, number>
  cases: Array<{ case_id: string; mitre: string; status: string; message: string; duration_ms: number }>
}
