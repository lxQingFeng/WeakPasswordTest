import logging
import os
from typing import List, Optional


class DictionaryLoader:
    def __init__(self):
        self.logger = logging.getLogger('dictionary_loader')

    def load_passwords(self, file_path: str) -> List[str]:
        # 从文件加载密码字典并过滤无效条目
        passwords = []
        if not file_path or not os.path.exists(file_path):
            self.logger.error(f"密码字典文件不存在: {file_path}")
            return passwords

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password and password not in passwords:
                        passwords.append(password)

            self.logger.info(f"成功加载密码字典，共 {len(passwords)} 个密码")
        except Exception as e:
            self.logger.error(f"加载密码字典失败: {str(e)}")

        return passwords

    def generate_simple_dictionary(self, output_path: str, min_length: int = 4, max_length: int = 8) -> bool:
        # 生成简单密码字典（仅数字组合）
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for length in range(min_length, max_length + 1):
                    for num in range(10 ** length):
                        password = f"{num:0{length}d}"
                        f.write(f"{password}\n")

            self.logger.info(f"简单密码字典生成成功: {output_path}")
            return True
        except Exception as e:
            self.logger.error(f"生成密码字典失败: {str(e)}")
            return False


# 保留原有函数接口以便向后兼容

def load_password_dictionary(file_path: str) -> List[str]:
    loader = DictionaryLoader()
    return loader.load_passwords(file_path)

def generate_simple_dictionary(output_path: str, min_length: int = 4, max_length: int = 8) -> bool:
    loader = DictionaryLoader()
    return loader.generate_simple_dictionary(output_path, min_length, max_length)