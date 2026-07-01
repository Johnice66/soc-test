let csrfToken = readCookie('soc_csrf')

function readCookie(name: string) {
  return document.cookie.split('; ').find((item) => item.startsWith(`${name}=`))?.split('=')[1] ?? ''
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers = new Headers(options.headers)
  if (options.body) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD'].includes(method.toUpperCase())) {
    csrfToken = csrfToken || readCookie('soc_csrf')
    if (csrfToken) headers.set('X-CSRF-Token', decodeURIComponent(csrfToken))
  }
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' })
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: response.statusText }))
    throw new ApiError(response.status, body.detail ?? '请求失败')
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export async function login(username: string, password: string) {
  const result = await api<{ user: import('./types').User; csrf_token: string }>('/api/auth/login', {
    method: 'POST', body: JSON.stringify({ username, password }),
  })
  csrfToken = result.csrf_token
  return result.user
}

export function clearCsrf() {
  csrfToken = ''
}
