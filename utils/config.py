import yaml
import os
import logging
from typing import Dict, Any, Optional


class Config:
    def __init__(self):
        self.logger = logging.getLogger('config')
        self.config = {}
        self.default_config = {
            'timeout': 10,
            'max_workers': 5,
            'log_level': 'INFO',
            'protocols': {
                'ssh': {'port': 22, 'enabled': True},
                'rdp': {'port': 3389, 'enabled': True},
                'web': {'port': 80, 'enabled': True}
            }
        }

    def load_from_file(self, config_path: str) -> bool:
        """从配置文件加载配置"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f)
                self.logger.info(f"配置文件加载成功: {config_path}")
                return True
            else:
                self.logger.warning(
                    f"配置文件 {config_path} 不存在，使用默认配置")
                self.config = self.default_config
                return False
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {str(e)}")
            self.config = self.default_config
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = self.config
        try:
            for key_part in keys:
                value = value[key_part]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """设置配置值"""
        keys = key.split('.')
        config = self.config
        for key_part in keys[:-1]:
            if key_part not in config:
                config[key_part] = {}
            config = config[key_part]
        config[keys[-1]] = value

    def save_to_file(self, config_path: str) -> bool:
        """保存配置到文件"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(self.config, f, allow_unicode=True, sort_keys=False)
            self.logger.info(f"配置已保存到 {config_path}")
            return True
        except Exception as e:
            self.logger.error(f"保存配置文件失败: {str(e)}")
            return False

    def validate(self) -> bool:
        """验证配置是否有效"""
        try:
            # 检查必要的配置项
            required_sections = ['timeout', 'max_workers', 'protocols']
            for section in required_sections:
                if section not in self.config:
                    self.logger.error(f"配置缺少必要部分: {section}")
                    return False
            return True
        except Exception as e:
            self.logger.error(f"配置验证失败: {str(e)}")
            return False