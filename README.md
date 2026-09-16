# DiskFight
---

## 📋 项目状态

| 项目 | 状态 |
|------|------|
| **当前阶段** | 阶段二任务 1—9 |
| **完成情况** | ✅ 全部完成并通过自动化回归测试 |
| **证据材料** | `evidence/`、`SECURITY_TEST_RECORD.md`、`security.log` |

---

## 🏗️ 项目架构

```
DiskFight/
│
├── app.py                  # Flask 主程序（已加固）
│   ├── /                   # 首页
│   ├── /register           # 注册接口
│   │                       #   ├─ 已增加密码复杂度校验
│   │                       #   ├─ 已修复 SQL 注入
│   │                       #   └─ 已增加异常处理
│   ├── /login              # 登录接口
│   │                       #   ├─ 已增加失败锁定 + 频率限制
│   │                       #   ├─ 已修复 SQL 注入
│   │                       #   └─ 已增加异常处理
│   ├── /listfiles          # 文件列表（需登录）
│   ├── /upload             # 文件上传（需登录）
│   ├── /download           # 文件下载（登录 + 归属 + 路径边界）
│   ├── /delete             # 文件删除（登录 + CSRF + 归属）
│   └── /logout             # POST退出并销毁会话
│
├── templates/              # 前端页面模板
│   ├── login.html          # 登录页面
│   ├── register.html       # 注册页面（已增加前端实时密码校验）
│   ├── filelist.html       # 文件列表页面
│   └── upload.html         # 文件上传页面
│
└── static/                 # 静态资源
    ├── css/
    │   └── style.css       # 全局样式
    └── js/
        └── register        # 注册相关脚本
```

---

## 🔐 安全加固概览

| 风险类型 | 状态 | 说明 |
|----------|------|------|
| SQL 注入 | ✅ 已修复 | 注册、登录接口均采用参数化查询 |
| CSRF | ✅ 已修复 | 已加入 CSRF 防护 |
| 密码强度 | ✅ 已加固 | 后端复杂度校验 + 前端实时校验 |
| 暴力破解 | ✅ 已加固 | 登录失败锁定 + 频率限制 |
| 异常处理 | ✅ 已完善 | 关键接口增加异常捕获 |
| XSS | ✅ 已验证 | 固定模板 + Jinja2 自动转义 |
| 越权与路径穿越 | ✅ 已修复 | Session确定用户，UUID文件标识，规范路径校验 |
| 危险文件上传 | ✅ 已修复 | 扩展名白名单、文件头校验、10MB限制、随机重命名 |
| SSTI | ✅ 已验证 | 用户输入只作为变量，不使用动态模板字符串 |
| 命令执行 | ✅ 已审计 | 无Shell调用；静态回归测试防止引入危险API |
| 会话与Cookie | ✅ 已加固 | 会话更新、POST登出、HttpOnly、SameSite=Lax |

---

## 🚀 启动方式

```bash
# 1. 安装依赖
pip install flask pymysql

# 2. 默认使用项目目录下的 SQLite 数据库 disk.db，无需额外启动数据库

# 3. 启动服务
python app.py

# 4. 访问
http://localhost:5000
```

生产环境启动前应设置随机密钥；HTTPS部署时同时开启Secure Cookie：

```powershell
$env:FLASK_SECRET_KEY = "请替换为至少32字节的随机密钥"
$env:COOKIE_SECURE = "1"
python app.py
```

如需使用 MySQL，先创建数据库和 users 表，再设置 `DB_DRIVER=mysql`、`DB_PASSWORD` 等数据库环境变量后启动。

## 🧪 安全回归测试

```powershell
python -m unittest discover -s tests -v
```

当前共 9 项测试，覆盖任务5—9的关键验收点。完整实验过程与课堂汇报证据见 `SECURITY_TEST_RECORD.md` 和 `evidence/`。

---
## 📁 报告相关

### 漏洞报告、安全加固报告与截图

- 任务1—4：原有报告草稿与Git标签保留。
- 任务5—9：已补充实验记录、自动化测试输出和两张汇报截图。
- 最终结题验收报告位于交付目录，个人姓名、学号、学院签字等未知信息留空。

---

## 📝 Git Tag 说明

```bash
vuln-weakpwd    # 修复前版本（存在弱口令漏洞）
fixed-weakpwd   # 修复后版本（已加固弱口令漏洞方面的问题）
fixed-sql       # 修复后版本（已修复SQL注入 + 错误信息泄露）
fixed-csrf       # 修复后版本（有漏洞但攻击未成功，仍然修复了的版本）
```
> 说明： 由于未检出 XSS 方面漏洞，因此未单独设立 XSS 相关标签。

查看方式：
```bash
git checkout vuln-weakpwd   # 切换到修复前版本
git checkout fixed-weakpwd  # 切换到修复后版本
```
