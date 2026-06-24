"""
被测主机 SSH 执行器（paramiko）
- 用于在被测主机上产生真实的安全事件日志（SSH 爆破、新增用户、计划任务等）
- 内置 dry-run 模式：只记录命令，不执行
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

try:
    import paramiko
except ImportError:  # 延迟到使用时报错
    paramiko = None  # type: ignore


@dataclass
class SSHResult:
    cmd: str
    exit_code: int
    stdout: str
    stderr: str
    elapsed_ms: float
    dry_run: bool = False


class SSHRunner:
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: str = "",
        private_key_path: str = "",
        dry_run: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.dry_run = dry_run
        self._client: Optional["paramiko.SSHClient"] = None
        self.history: list[SSHResult] = []

    def _connect(self):
        if paramiko is None:
            raise RuntimeError("paramiko 未安装")
        if self._client:
            return
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {"hostname": self.host, "port": self.port, "username": self.username, "timeout": 10}
        if self.private_key_path:
            kwargs["key_filename"] = self.private_key_path
        elif self.password:
            kwargs["password"] = self.password
        c.connect(**kwargs)
        self._client = c

    def run(self, cmd: str, timeout: int = 30) -> SSHResult:
        if self.dry_run:
            r = SSHResult(cmd=cmd, exit_code=0, stdout="[DRY-RUN] not executed", stderr="", elapsed_ms=0, dry_run=True)
            self.history.append(r)
            return r
        self._connect()
        t0 = time.perf_counter()
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)  # type: ignore
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        rc = stdout.channel.recv_exit_status()
        r = SSHResult(
            cmd=cmd, exit_code=rc, stdout=out[:2000], stderr=err[:2000],
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )
        self.history.append(r)
        return r

    def close(self):
        if self._client:
            self._client.close()
            self._client = None
