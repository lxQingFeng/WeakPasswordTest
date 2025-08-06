# 弱口令检测工具

## 项目介绍
弱口令检测工具是一款用于检测网络服务弱口令的安全工具，支持 SSH 协议的弱口令检测。该工具能够批量检测目标主机的弱密码问题，并生成直观的 HTML 格式检测报告。

## 功能特点
- **并发检测**：基于 asyncio 的异步检测机制，多线程并发检测，提高检测效率。
- **灵活配置**：支持通过配置文件自定义检测参数，如连接超时时间、最大并发工作线程数、日志级别等。
- **详细报告**：生成 HTML 格式的检测报告，包含检测摘要（总检测数、成功数、失败数）、详细结果列表（目标、协议、用户名、密码状态等）以及可视化统计图表。
- **密码字典管理**：支持自定义密码字典，可直接编辑默认密码字典文件，也可使用工具生成简单密码字典，还能通过命令行参数指定其他密码字典文件。

## 环境要求
- Python 3.8+ 

## 安装指南
### 安装步骤
1. 克隆或下载本项目到本地
2. 安装依赖包：
```bash
pip install -r requirements.txt
```

## 配置说明
### 配置文件
工具使用 `config.yaml` 文件进行配置，主要配置项包括：
```yaml
# 连接超时时间(秒)
timeout: 10
# 最大重试次数
max_retries: 2
# 最大工作线程数
max_workers: 5
# 协议配置
protocols:
  ssh:
    port: 22
    enabled: true
  web:
    port: 80
    enabled: true

# 报告配置
report:
  format: html
  include_details: true
  output_dir: reports

# 并发控制配置
concurrency:
  type: async
  max_tasks: 10

# 安全相关配置
security:
  encrypt_sensitive_data: true
  log_sensitive_data: false
  audit_log_enabled: true
```

### 密码字典
默认密码字典为 `passwords.txt`，每行一个密码。可以：
- 直接编辑该文件添加自定义密码
- 使用 `utils/dictionary_loader.py` 生成简单密码字典
- 通过命令行参数指定其他密码字典文件

## 使用方法
### 准备文件
1. **目标文件** (`targets.txt`)：每行包含一个目标 IP 地址，格式为 `IP地址`。示例：
```
192.168.1.1
192.168.1.2
192.168.32.141
```
2. **密码字典** (`passwords.txt`)：每行包含一个待尝试的密码。
3. **配置文件** (`config.yaml`)：工具配置参数。

### 命令行参数
```
usage: main.py [-h] (-t TARGET_FILE | -T TARGET) (-U USERNAME_FILE | -u USERNAME) -p PASSWORD_FILE [-P PROTOCOLS [PROTOCOLS ...]] [-o REPORT_FILE]

弱口令检测工具 - 支持SSH协议检测

optional arguments:
  -h, --help            显示帮助信息
  -t TARGET_FILE, --target-file TARGET_FILE
                        包含目标列表的文件路径
  -T TARGET, --target TARGET
                        单个目标IP地址
  -U USERNAME_FILE, --username-file USERNAME_FILE
                        包含用户名列表的文件路径
  -u USERNAME, --username USERNAME
                        单个用户名
  -p PASSWORD_FILE, --password_file PASSWORD_FILE
                        密码字典文件路径
  -P PROTOCOLS [PROTOCOLS ...], --protocols PROTOCOLS [PROTOCOLS ...]
                        要检测的协议，可选值: ssh
  -o REPORT_FILE, --report-file REPORT_FILE
                        检测报告输出路径
```

### 使用示例
```bash
# 检测所有支持的协议，使用目标文件和单个用户名
python main.py -t targets.txt -u admin -p passwords.txt

# 检测所有支持的协议，使用单个目标和用户名文件
python main.py -T 192.168.1.1 -U username.txt -p passwords.txt

# 仅检测 SSH 协议
python main.py -t targets.txt -u root -p passwords.txt -P ssh

# 指定输出报告文件
python main.py -t targets.txt -u admin -p passwords.txt -o results.html
```

## 输出报告
检测完成后，工具会生成 HTML 格式的检测报告，包含以下信息：
- 检测摘要（总检测数、成功数、失败数）
- 详细结果列表（目标、协议、用户名、密码状态等）
- 可视化统计图表

## 项目结构
```
WeakPasswordTest/
├── main.py              # 主程序入口
├── requirements.txt     # 依赖包列表
├── config.yaml          # 配置文件
├── passwords.txt        # 默认密码字典
├── detectors/           # 各协议检测模块
│   └── ssh_detector.py  # SSH 检测模块
└── utils/               # 工具类模块
    ├── config.py        # 配置管理
    ├── logger.py        # 日志管理
    ├── result_handler.py # 结果处理与报告生成
    └── dictionary_loader.py # 密码字典加载
```

## 安全与合规
- 本工具仅用于授权环境的安全测试
- 使用前请确保您已获得合法授权
- 请勿用于未授权的网络或系统

## 注意事项
- 大量并发连接可能被目标系统视为攻击行为
- 本工具仅用于授权的安全测试，未经授权使用可能违反法律法规
- 请勿对未授权系统进行检测
- 使用时建议添加适当延迟，避免被目标系统屏蔽
- 敏感环境下建议使用 VPN 或代理隐藏真实 IP
- 密码字典应包含常见弱口令如`123456`、`password`、`admin`等

## 许可证
[MIT License](LICENSE)
