import json
import csv
import logging
from datetime import datetime
from typing import List, Dict, Any
import os


class ResultHandler:
    def __init__(self):
        self.results = []
        self.logger = logging.getLogger('result_handler')

    def add_result(self, protocol: str, target: str, port, username: str, password: str, success: bool,
                   error: str = None):
        """添加检测结果"""
        result = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': protocol,
            'target': target,
            'port': port,
            'username': username,
            'password': password,
            'success': success,
            'error': error
        }
        self.results.append(result)
        self.logger.info(
            f"添加检测结果 - 协议: {protocol}, 目标: {target}, 成功: {success}")

    def save_results(self, output_file: str):
        """保存结果到文件"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            # 保存为JSON格式
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
            self.logger.info(f"检测结果已保存到 {output_file}")
        except Exception as e:
            self.logger.error(f"保存结果失败: {str(e)}")

    def generate_report(self, report_file: str):
        """生成HTML格式的检测报告"""
        try:
            html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>弱口令检测报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; color: #333; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .result-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .result-table th, .result-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .result-table th {{ background-color: #f2f2f2; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .failure {{ color: #e74c3c; }}
    </style>
</head>
<body>
    <h1>弱口令检测报告</h1>
    <p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="summary">
        <h2>检测摘要</h2>
        <p>总检测目标: {len(self.results)}</p>
        <p>成功检测到弱口令: {sum(1 for r in self.results if r['success'])}</p>
        <p>检测失败: {sum(1 for r in self.results if not r['success'])}</p>
    </div>

    <h2>详细结果</h2>
    <table class="result-table">
        <tr>
            <th>时间戳</th>
            <th>协议</th>
            <th>目标</th>
            <th>端口</th>
            <th>用户名</th>
            <th>密码</th>
            <th>结果</th>
        </tr>
        {self._generate_table_rows()}
    </table>
</body>
</html>"""

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"检测报告已生成: {report_file}")
        except Exception as e:
            self.logger.error(f"生成报告失败: {str(e)}")

    def _generate_table_rows(self):
        """生成报告中的表格行"""
        rows = []
        for result in self.results:
            status = "<span class='success'>成功</span>" if result['success'] else "<span class='failure'>失败</span>"
            password = result['password'] if result['password'] else "N/A"
            rows.append(
                f"<tr><td>{result['timestamp']}</td><td>{result['protocol']}</td><td>{result['target']}</td><td>{result['port']}</td><td>{result['username']}</td><td>{password}</td><td>{status}</td></tr>")
        return '\n        '.join(rows)