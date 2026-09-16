# 阶段二任务5至9实验记录

## 测试边界

所有测试均针对本组本机 Flask 网盘，使用 Flask 测试客户端和临时目录，不访问公网、校园系统或其他小组系统。上传测试只使用固定文字的无害样本。

## 运行方式

```powershell
cd "C:\Users\lever\Desktop\Disk Fight\disk-"
python -m unittest discover -s tests -v
```

## 任务5 越权访问 IDOR 与路径穿越

- 未登录访问 `/listfiles`、`/upload`、`/download`、`/delete` 均返回 401。
- 文件目录由当前 Session 用户的哈希标识确定，不接受客户端传入用户名。
- 新上传文件使用服务端生成的 `32位十六进制UUID.扩展名`；为兼容历史文件，旧安全文件名仍可访问，但路径必须是当前用户目录下的直接子文件，`../course_outside_file.txt` 返回 403。
- user1 上传后生成的文件标识，在 user2 会话中访问返回 404。

## 任务6 文件上传与 WebShell 风险

- `test.php` 无害标记样本返回 415，危险扩展名被拒绝。
- 文本伪装的 `fake.png` 返回 415，证明后端检查了文件头而非只相信扩展名或 Content-Type。
- 合法 UTF-8 文本上传成功，保存名改为随机 UUID，原文件名仅作为展示元数据。
- 单文件限制 10MB，上传目录不映射为静态执行目录，下载统一经过鉴权接口。
- 日志记录上传者、来源 IP、原名、保存名、大小、检测类型和拒绝原因。

## 任务7 SSTI 模板注入

- 项目只使用固定模板文件和变量传值，不使用 `render_template_string`。
- 将 `{{7*7}}` 作为用户名变量渲染时，页面保留原文本，不会计算为 49。
- Jinja2 自动转义继续承担 XSS 输出编码，SSTI 与 XSS 分别验证。

## 任务8 命令执行与 Shell 调用

- 静态审计确认项目未使用 `os.system`、`os.popen`、`subprocess(..., shell=True)`。
- 网盘当前没有压缩、缩略图或外部命令功能，因此不强行增加危险接口。
- 后续如实现压缩，应优先使用 Python `zipfile` 标准库；必须调用外部程序时使用参数数组和 `shell=False`。

## 任务9 会话与 Cookie

- 登录成功前清空旧会话并生成新的随机 CSRF Token；会话有效期 30 分钟。
- 退出改为带 CSRF 的 POST，请求后 `session.clear()` 并删除会话 Cookie。
- Cookie 配置为 HttpOnly、SameSite=Lax；生产 HTTPS 环境通过 `COOKIE_SECURE=1` 开启 Secure。
- 登录用户页面发送 `Cache-Control: no-store`，降低退出后缓存显示风险。

## 证据索引

- 自动化测试输出：`evidence/test-results.txt`
- 测试结果截图：`evidence/01-security-tests.png`
- 加固功能摘要：`evidence/02-hardening-summary.png`
- 应用安全日志：`security.log`

## 仍需说明

当前数据库中的历史密码仍为明文，这是原项目遗留问题。正式部署前应使用 Werkzeug 的 PBKDF2 或 bcrypt 迁移密码哈希；本次任务5至9不改变数据库结构，以避免破坏已有课程数据。
