import paramiko
import asyncio
import logging
import random
from typing import List, Dict, Optional, Union
from paramiko.ssh_exception import SSHException, NoValidConnectionsError, AuthenticationException, \
    PasswordRequiredException, BadHostKeyException, ChannelException


class SSHDetector:
    def __init__(self, timeout: int = 10, max_retries: int = 2, min_delay: float = 0.5, max_delay: float = 2.0):
        """
        初始化SSH检测器

        Args:
            timeout: 连接超时时间(秒)
            max_retries: 最大重试次数
            min_delay: 最小延迟时间(秒)
            max_delay: 最大延迟时间(秒)
        """
        if max_retries < 0:
            raise ValueError("重试次数不能为负数")
        if timeout <= 0:
            raise ValueError("超时时间必须大于0")

        # 验证延迟参数
        if min_delay < 0:
            raise ValueError("最小延迟不能为负数")
        if max_delay < min_delay:
            raise ValueError("最大延迟不能小于最小延迟")

        self.timeout = timeout
        self.max_retries = max_retries
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.logger = logging.getLogger('ssh_detector')
        self.ssh_client = None

    def _load_private_key(self, key_path: str, password: Optional[str] = None) -> paramiko.PKey:
        """
        加载私钥文件，支持多种密钥类型

        Args:
            key_path: 私钥文件路径
            password: 私钥密码

        Returns:
            加载成功的私钥对象

        Raises:
            SSHException: 当密钥加载失败时
        """
        key_types = [
            paramiko.RSAKey,
            paramiko.DSSKey,
            paramiko.ECDSAKey,
            paramiko.Ed25519Key
        ]

        for key_type in key_types:
            try:
                return key_type.from_private_key_file(key_path, password=password)
            except (paramiko.SSHException, IOError):
                continue

        self.logger.error(f"无法加载私钥文件: {key_path}，尝试了所有支持的密钥类型")
        raise paramiko.SSHException(f"无法加载私钥文件: {key_path}，不支持的密钥类型或文件格式")

    async def detect(self, target: str, port: int, username: str, passwords: Optional[List[str]] = None,
                     private_key_path: Optional[str] = None, private_key_password: Optional[str] = None) -> Dict:
        """
        检测SSH服务弱口令

        Args:
            target: 目标IP或主机名
            port: 端口号
            username: 用户名
            passwords: 密码列表
            private_key_path: 私钥文件路径
            private_key_password: 私钥密码

        Returns:
            检测结果字典
        """
        # 验证端口有效性
        if not (1 <= port <= 65535):
            error_msg = f"无效的端口号: {port}，必须在1-65535范围内"
            self.logger.error(error_msg)
            return {
                'target': target,
                'port': port,
                'username': username,
                'success': False,
                'password': None,
                'key_used': None,
                'error': error_msg
            }

        result = {
            'target': target,
            'port': port,
            'username': username,
            'success': False,
            'password': None,
            'key_used': None,
            'error': None
        }

        # 验证输入参数
        if not target or not username:
            error_msg = '目标地址和用户名不能为空'
            self.logger.error(error_msg)
            return {'error': error_msg, 'success': False}

        # 先尝试密钥认证（如果提供了密钥）
        if private_key_path:
            key_result = await self._try_key_authentication(target, port, username, private_key_path,
                                                            private_key_password)
            if key_result['success']:
                return key_result

        # 再尝试密码认证（如果提供了密码列表）
        if passwords:
            password_result = await self._try_password_authentication(target, port, username, passwords)
            if password_result['success']:
                return password_result

        # 记录最终结果
        if result['success']:
            self.logger.info(f"检测成功 - 目标: {target}:{port}, 用户名: {username}")
        else:
            self.logger.debug(f"检测失败 - 目标: {target}:{port}, 错误: {result.get('error')}")
        return result

    def __del__(self):
        """
        析构函数，确保所有资源被正确释放
        """
        try:
            if self.ssh_client and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active():
                self.ssh_client.close()
                self.logger.info("SSH连接已关闭")
        except Exception as e:
            self.logger.warning(f"关闭SSH连接时发生错误: {str(e)}")

    async def _try_key_authentication(self, target: str, port: int, username: str, key_path: str,
                                      key_password: Optional[str]) -> Dict:
        """
        尝试使用密钥文件进行认证

        Args:
            target: 目标IP或主机名
            port: 端口号
            username: 用户名
            key_path: 私钥文件路径
            key_password: 私钥密码

        Returns:
            认证结果字典
        """
        result = {
            'target': target,
            'port': port,
            'username': username,
            'success': False,
            'password': None,
            'key_used': key_path,
            'error': None
        }

        for attempt in range(self.max_retries):
            try:
                # 加载私钥
                private_key = await asyncio.to_thread(
                    self._load_private_key,
                    key_path,
                    password=key_password
                )

                # 创建SSH客户端
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # 连接到目标
                await asyncio.to_thread(
                    self.ssh_client.connect,
                    hostname=target,
                    port=port,
                    username=username,
                    key=private_key,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout
                )

                # 认证成功
                result['success'] = True
                self.logger.info(f"SSH密钥认证成功 - 目标: {target}, 用户名: {username}")
                self.ssh_client.close()
                return result

            except AuthenticationException as auth_ex:
                result['error'] = "密钥认证失败"
                self.logger.error(f"密钥认证失败: {auth_ex}")
                break
            except Exception as e:
                result['error'] = f"连接尝试 {attempt + 1} 失败: {str(e)}"
                self.logger.warning(result['error'])
                if attempt < self.max_retries - 1:
                    # 添加随机延迟避免被检测为暴力破解
                    jitter = random.uniform(self.min_delay, self.max_delay)
                    await asyncio.sleep(jitter)

        return result

    async def _try_password_authentication(self, target: str, port: int, username: str, passwords: List[str]) -> Dict:
        """
        尝试使用密码列表进行认证
        """
        result = {
            'target': target,
            'port': port,
            'username': username,
            'success': False,
            'password': None,
            'key_used': None,
            'error': None
        }

        for password in passwords:
            for attempt in range(self.max_retries):
                try:
                    # 创建SSH客户端
                    self.ssh_client = paramiko.SSHClient()
                    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # 连接到目标
                    await asyncio.to_thread(
                        self.ssh_client.connect,
                        hostname=target,
                        port=port,
                        username=username,
                        password=password,
                        timeout=self.timeout,
                        banner_timeout=self.timeout,
                        auth_timeout=self.timeout
                    )

                    # 认证成功
                    result['success'] = True
                    result['password'] = password
                    # 日志中脱敏显示密码
                    masked_password = '*' * len(password)
                    self.logger.warning(
                        f"SSH弱口令检测成功 - 目标: {target}, 用户名: {username}, 密码: {masked_password}")
                    self.ssh_client.close()
                    return result

                except AuthenticationException as auth_ex:
                    result['error'] = "身份验证失败"
                    self.logger.error(f"身份验证失败: {auth_ex}")
                    break
                except NoValidConnectionsError as conn_ex:
                    result['error'] = f"无法建立连接: {str(conn_ex)}"
                    self.logger.error(result['error'])
                    break
                except BadHostKeyException as host_key_ex:
                    result['error'] = f"主机密钥验证失败: {str(host_key_ex)}"
                    self.logger.error(result['error'])
                    break
                except SSHException as ssh_ex:
                    result['error'] = f"SSH协议错误: {str(ssh_ex)}"
                    self.logger.error(result['error'])
                    break
                finally:
                    if self.ssh_client and self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active():
                        self.ssh_client.close()

        return result