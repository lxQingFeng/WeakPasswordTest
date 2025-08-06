import argparse
import asyncio
import logging
import os
from dotenv import load_dotenv
from detectors.ssh_detector import SSHDetector

from utils.result_handler import ResultHandler
from utils.config import Config
from utils.dictionary_loader import DictionaryLoader
from utils.dictionary_loader import load_password_dictionary
from utils.logger import setup_logger

# 加载环境变量
load_dotenv()

# 设置日志
logger = setup_logger('weak_password_detector', 'detection.log')

import re


class WeakPasswordDetector:
    def is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式是否有效

        Args:
            ip: 待验证的IP地址字符串

        Returns:
            如果IP地址有效则返回True，否则返回False
        """
        ip_pattern = r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(ip_pattern, ip) is not None

    def __init__(self, password_file):
        self.config = Config()
        self.result_handler = ResultHandler()
        self.detectors = {
            'ssh': SSHDetector,
        }
        self.targets = []  # 初始化目标列表
        self.usernames = []  # 初始化用户名列表
        self.dictionary_loader = DictionaryLoader()  # 初始化字典加载器
        self.password_file = password_file  # 添加 password_file 属性

    def load_usernames(self, username_source):
        """加载用户名列表，可以是文件路径或单个用户名"""
        if os.path.isfile(username_source):
            try:
                with open(username_source, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logger.error(f"用户名文件 {username_source} 不存在")
                return []
        else:
            # 视为单个用户名
            return [username_source.strip()]

    def load_targets(self, target_source):
        """加载目标列表，可以是文件路径或单个目标IP"""
        if os.path.isfile(target_source):
            try:
                with open(target_source, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                logger.error(f"目标文件 {target_source} 不存在")
                return []
        else:
            # 如果不是文件路径，则视为单个目标IP
            return [target_source.strip()]

    async def run_detection(self, protocol, target, username, password_list):
        """执行指定协议的弱口令检测"""
        if protocol not in self.detectors:
            logger.error(f"不支持的协议: {protocol}")
            return

        port = self.config.get(f'protocols.{protocol}.port', 0)
        # 验证IP地址格式
        if not self.is_valid_ip(target):
            logger.error(f"无效的IP地址格式: {target}")
            return
        # 根据协议类型决定是否传入max_retries参数
        detector = self.detectors[protocol](
            timeout=self.config.get('timeout', 10),
            max_retries=self.config.get('max_retries', 3)
        )

        try:
            # 添加任务超时控制，防止长时间无响应
            result = await asyncio.wait_for(detector.detect(target, port, username, password_list), timeout=30)

            if result['success']:
                logger.warning(
                    f"弱口令检测成功 - 协议: {protocol}, 目标: {target}, 用户名: {username}, 密码: {result['password']}")
                self.result_handler.add_result(protocol, target, port, username, result['password'], result['success'],
                                               result.get('error'))
            else:
                logger.info(
                    f"弱口令检测完成 - 协议: {protocol}, 目标: {target}, 用户名: {username}, 未发现弱口令")
        except Exception as e:
            logger.error(f"检测过程中发生错误: {str(e)}")

    async def main(self, args):
        # 加载配置
        self.config.load_from_file('config.yaml')

        # 加载目标列表
        # 处理目标输入
        if args.target_file:
            targets = self.load_targets(args.target_file)
        else:
            targets = [args.target] if args.target else []
        if not targets:
            logger.error("未找到检测目标，请检查目标文件")
            return

        # 加载用户名
        if args.username_file:
            usernames = self.load_usernames(args.username_file)
        else:
            usernames = [args.username] if args.username else []

        # 加载密码字典
        passwords = load_password_dictionary(self.password_file)
        if not passwords:
            logger.error("未找到有效密码字典")
            return

        # 执行检测任务
        tasks = []
        for target in targets:
            for username in usernames:
                for protocol in args.protocols:
                    tasks.append(self.run_detection(protocol, target, username, passwords))

        await asyncio.gather(*tasks)

        # 检测完成后添加总结日志
        if self.result_handler.results:
            logger.warning(f"弱口令检测完成，共发现 {len(self.result_handler.results)} 个弱口令")
        else:
            logger.info("弱口令检测完成，未发现任何弱口令")

        # 生成检测报告
        self.result_handler.generate_report(args.report_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='弱口令检测工具 - 支持SSH协议检测')
    # 目标参数组（互斥）
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target-file', help='包含目标列表的文件路径')
    target_group.add_argument('-T', '--target', help='单个目标IP地址')

    # 用户名参数组（互斥）
    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument('-U', '--username-file', help='包含用户名列表的文件路径')
    user_group.add_argument('-u', '--username', help='单个用户名')
    parser.add_argument('-p', '--password_file', required=True,
                        help='密码字典文件路径')
    parser.add_argument('-P', '--protocols', nargs='+', default=['ssh'], help='要检测的协议，可选值: ssh')
    parser.add_argument('-o', '--report-file', default='report.html',
                        help='检测报告输出路径')
    args = parser.parse_args()

    # 添加参数验证
    if not os.path.exists(args.password_file):
        logger.error(f"密码文件不存在: {args.password_file}")
        import sys
        sys.exit(1)

    detector = WeakPasswordDetector(args.password_file)  # 传递 password_file 参数

    asyncio.run(detector.main(args))