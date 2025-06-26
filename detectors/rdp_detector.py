import win32ts
import win32security
import win32con
import logging
from typing import List, Dict, Optional

class RDPDetector:
    def __init__(self, target, username, passwords, timeout: int = 10, max_workers: int = 5):
        self.target = target
        self.username = username
        self.passwords = passwords
        self.timeout = timeout
        self.max_workers = max_workers
        self.logger = logging.getLogger('rdp_detector')

    async def detect(self) -> Dict:
        """检测指定目标的 RDP 弱口令"""
        result = {
            'target': self.target,
            'username': self.username,
            'success': False,
            'password': None,
            'error': None
        }

        for password in self.passwords:
            try:
                domain = ""  # 如果有域名可以填写
                logon_type = win32con.LOGON32_LOGON_NETWORK
                logon_provider = win32con.LOGON32_PROVIDER_DEFAULT

                token = win32security.LogonUser(
                    self.username,
                    domain,
                    password,
                    logon_type,
                    logon_provider
                )

                if token:
                    result['success'] = True
                    result['password'] = password
                    self.logger.info(
                        f"RDP 弱口令检测成功 - 目标: {self.target}, 用户名: {self.username}, 密码: {password}")
                    token.Close()
                    break

            except Exception as e:
                self.logger.debug(f"尝试密码 {password} 失败: {str(e)}")
                continue

        return result