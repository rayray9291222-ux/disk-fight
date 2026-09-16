# 阶段二任务5至9漏洞报告与安全加固报告

测试环境：本机授权Flask课程靶场；测试日期：2026-09-16。测试账号使用user1、user2等课程测试标识。姓名、学号、小组名等个人信息留空。全部测试均为无害验证，不读取系统敏感文件，不使用真实WebShell，不调用系统命令。

## 任务5 越权访问 IDOR 与文件读取

### 漏洞报告

- 漏洞类型：路径穿越导致越权删除；文件归属校验不统一。
- 漏洞位置：`POST /delete`，参数`filename`；同时复核`GET /download`。
- 修复前现象：删除接口通过`os.path.join(user_dir, filename)`拼接路径，并用`os.path.exists`后直接删除。若`filename`含`../`，规范路径可能离开当前用户目录。
- 无害复现：登录user1，在临时课程目录准备`course_outside_file.txt`；提交`filename=../course_outside_file.txt`；只观察响应与文件是否保留。
- 影响：攻击者在已登录前提下可能删除当前用户目录上级中的可达文件。影响取决于服务进程文件权限，不夸大为服务器完全控制。
- 根因：客户端文件名被直接用于文件系统路径；未做规范化路径边界校验；下载与删除未复用统一资源校验函数。

### 安全加固报告

- 身份只从Session读取，不接受客户端传入用户目录。
- 新上传文件使用UUID存储名；历史文件只允许安全的单段文件名。
- `resolve_owned_file()`先拒绝目录分隔与异常标识，再调用`Path.resolve()`，并验证目标仍位于当前用户目录。
- user1与user2使用独立目录，user2访问user1的UUID返回404。
- 原路径穿越参数在下载和删除接口均返回403，外部测试文件仍存在。

## 任务6 文件上传漏洞 WebShell与木马文件识别

### 漏洞报告

- 漏洞类型：任意文件上传、伪装文件上传、可控存储文件名。
- 漏洞位置：`POST /upload`，文件字段`file`，可选字段`customName`。
- 修复前现象：后端只调用`secure_filename`，没有扩展名白名单、文件头检查或大小限制，随后按用户提供的名称保存。
- 无害样本：`test.php`内容为`COURSE_UPLOAD_TEST_ONLY`；`fake.png`内容为`COURSE_FAKE_IMAGE_TEST`。
- 影响：可在上传目录中存放与业务无关的脚本或伪装文件；Flask默认不会执行上传的PHP/JSP，但文件若被错误映射到其他可执行Web容器会放大风险。
- 根因：只处理文件名字符，没有验证类型、内容、体积和存储位置。

### 安全加固报告

- 后端白名单仅允许txt、pdf、png、jpg、jpeg、zip。
- PNG、JPEG、PDF、ZIP检查固定文件头；TXT拒绝NUL字节并要求头部可按UTF-8解码。
- Flask设置`MAX_CONTENT_LENGTH=10MB`。
- 保存名改为随机UUID，原名只写入JSON元数据用于展示和下载名。
- 上传目录没有静态路由，只能经过已登录的下载接口访问，因此不会被Flask当作脚本执行。
- 日志记录上传者、来源IP、原名、保存名、大小、检测类型与拒绝原因，不记录密码、Cookie或Token。
- 修复后`test.php`和`fake.png`均返回415，合法UTF-8文本上传成功。

## 任务7 SSTI模板注入

### 测试与结论

- 项目使用Flask/Jinja2固定模板文件，通过`render_template()`传递变量。
- 审计未发现`render_template_string`或把用户输入拼接成模板源码的写法。
- 无害探测：把`{{7*7}}`作为会话用户名变量渲染文件列表页。
- 结果：页面显示原始`{{7*7}}`，未计算为49，因此当前输入点不存在SSTI。

### 加固措施

- 保持固定模板与变量传值模式。
- 自动化测试禁止在`app.py`中引入`render_template_string(`。
- XSS由Jinja2自动转义处理，SSTI与XSS分别判断，不把浏览器执行和服务端模板执行混为一谈。

## 任务8 命令执行与Shell调用

### 代码审计与结论

- 审计`app.py`及当前功能，未发现`os.system`、`os.popen`、`subprocess(..., shell=True)`或外部压缩/缩略图命令。
- 项目没有必须调用系统Shell的功能，按任务要求完成代码审计说明，不强行增加危险接口，也不执行命令注入探测。

### 防御设计

- 将危险API关键字纳入自动化静态回归测试。
- 将来实现压缩下载时优先使用Python`zipfile`；必须调用外部程序时使用固定可执行文件、参数数组、`shell=False`和最小权限账号。
- 服务器错误只写日志，不向浏览器返回命令输出、系统路径或环境变量。

## 任务9 会话管理 登出与Cookie安全

### 问题报告

- 修复前使用仓库中的固定`app.secret_key`，可预测且不适合部署。
- `GET /logout`只执行`session.pop('user')`，没有清空CSRF令牌等会话状态，且GET请求可被跨站触发。
- 未显式设置会话有效期、SameSite、Secure和已登录页面缓存策略。

### 安全加固报告

- 生产密钥从`FLASK_SECRET_KEY`读取；未配置时开发环境每次启动生成临时随机密钥。
- 登录成功后执行`session.clear()`，设置30分钟会话有效期，并生成新的64位十六进制CSRF令牌，使登录前后Cookie值变化。
- 登出改为带CSRF令牌的POST，执行`session.clear()`并删除会话Cookie。
- 设置`SESSION_COOKIE_HTTPONLY=True`、`SESSION_COOKIE_SAMESITE='Lax'`；HTTPS部署通过`COOKIE_SECURE=1`启用Secure。
- 已登录响应增加`Cache-Control: no-store`。
- 未登录访问核心接口返回401；退出后再次访问`/listfiles`返回401；Cookie测试确认包含HttpOnly和SameSite=Lax。

## 修复后统一验证

运行：

```powershell
python -m unittest discover -s tests -v
```

结果：9项测试全部通过。原始输出位于`evidence/test-results.txt`，课堂截图位于`evidence/01-security-tests.png`和`evidence/02-hardening-summary.png`。

## 仍需改进

原项目数据库仍使用明文密码字段。正式部署前应设计密码哈希迁移方案并使用PBKDF2或bcrypt；登录失败计数目前位于单进程内存，多实例部署时应迁移到Redis等共享存储；上线时必须启用HTTPS与Secure Cookie。
