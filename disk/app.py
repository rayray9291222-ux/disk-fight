from flask import Flask, request, render_template, session, redirect, url_for
from flask import send_from_directory, abort
from werkzeug.utils import secure_filename
import json
import logging
import os
import re
import secrets
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pymysql


app = Flask(__name__)

# 生产环境必须通过环境变量提供固定随机密钥。开发环境每次启动生成临时密钥，
# 避免把可预测密钥提交到仓库。
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "upload")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "zip"}
METADATA_FILENAME = ".metadata.json"

login_attempts = {}
request_history = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 10

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("security.log", encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

db_config = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "my_database"),
    "charset": "utf8mb4",
}


def get_db_connection():
    driver = os.environ.get("DB_DRIVER", "sqlite").lower()
    if driver == "mysql":
        try:
            return pymysql.connect(**db_config)
        except pymysql.Error as error:
            logger.warning("mysql_connect_fallback_to_sqlite error=%s", error)

    connection = sqlite3.connect(os.environ.get("SQLITE_DB_PATH", "disk.db"))
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(40) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def valid_csrf_token(value):
    expected = session.get("csrf_token", "")
    return bool(value and expected and secrets.compare_digest(value, expected))


def current_user_directory():
    user = session.get("user")
    if not user:
        abort(401)
    # 用户目录只采用清洗后的单段名称，兼容原项目已有 upload/用户名 目录。
    directory_key = secure_filename(user)
    if not directory_key:
        abort(403, description="用户名不能映射为安全目录")
    root = Path(app.config["UPLOAD_FOLDER"]).resolve()
    user_dir = (root / directory_key).resolve()
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir


def resolve_owned_file(stored_name):
    """把客户端文件标识限制在当前用户目录的直接子文件中。"""
    if not stored_name or stored_name != Path(stored_name).name:
        abort(403, description="非法文件路径")
    if (
        stored_name == METADATA_FILENAME
        or stored_name.startswith(".")
        or len(stored_name) > 120
        or secure_filename(stored_name) != stored_name
    ):
        abort(403, description="非法文件标识")

    user_dir = current_user_directory()
    target = (user_dir / stored_name).resolve()
    try:
        target.relative_to(user_dir)
    except ValueError:
        abort(403, description="非法文件路径")
    return user_dir, target


def metadata_path(user_dir):
    return user_dir / METADATA_FILENAME


def load_metadata(user_dir):
    path = metadata_path(user_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        logger.warning("metadata_read_failed user=%s", session.get("user"))
        return {}


def save_metadata(user_dir, data):
    path = metadata_path(user_dir)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def detected_file_type(extension, header):
    if extension == "png" and header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if extension in {"jpg", "jpeg"} and header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if extension == "pdf" and header.startswith(b"%PDF-"):
        return "application/pdf"
    if extension == "zip" and header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "application/zip"
    if extension == "txt" and b"\x00" not in header:
        try:
            header.decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            return None
    return None


@app.errorhandler(413)
def file_too_large(_error):
    return "文件过大，单文件不能超过10MB", 413


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; script-src 'self' 'unsafe-inline'",
    )
    if "user" in session:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html", csrf_token=ensure_csrf_token())


@app.route("/register", methods=["POST"])
def register():
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "CSRF校验失败", 403

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not re.fullmatch(r"[\w\-\u4e00-\u9fff]{1,40}", username):
        return "用户名只能包含中英文、数字、下划线和连字符，长度1至40位", 400
    if len(password) < 8:
        return "密码长度至少8位", 400
    if not re.search(r"[A-Z]", password):
        return "密码需包含大写字母", 400
    if not re.search(r"[a-z]", password):
        return "密码需包含小写字母", 400
    if not re.search(r"[0-9]", password):
        return "密码需包含数字", 400
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "密码需包含特殊字符", 400

    conn = get_db_connection()
    placeholder = "%s" if os.environ.get("DB_DRIVER", "sqlite").lower() == "mysql" else "?"
    sql = f"INSERT INTO users (username, password) VALUES ({placeholder}, {placeholder})"
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (username, password))
        conn.commit()
        return render_template("message.html", title="注册成功", message="账号已创建，请登录。", link="/login")
    except (pymysql.IntegrityError, sqlite3.IntegrityError):
        return render_template("message.html", title="注册失败", message="用户名已存在。", link="/register"), 409
    except (pymysql.Error, sqlite3.Error) as error:
        logger.error("database_error action=register user=%s error=%s", username, error)
        return "系统错误，请稍后重试", 500
    finally:
        cursor.close()
        conn.close()


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html", csrf_token=ensure_csrf_token())


@app.route("/login", methods=["POST"])
def login_post():
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "CSRF校验失败", 403

    client_ip = request.remote_addr or "unknown"
    now = datetime.now()
    request_history[client_ip] = [
        timestamp for timestamp in request_history[client_ip]
        if now - timestamp < timedelta(minutes=1)
    ]
    if len(request_history[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
        logger.warning("login_rate_limited ip=%s", client_ip)
        return "请求过于频繁，请等待1分钟后再试", 429
    request_history[client_ip].append(now)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    record = login_attempts.get(username)
    if record and record.get("locked_until") and record["locked_until"] > now:
        remain = (record["locked_until"] - now).seconds // 60
        return f"账号已锁定，请等待 {remain + 1} 分钟后重试", 423

    conn = get_db_connection()
    placeholder = "%s" if os.environ.get("DB_DRIVER", "sqlite").lower() == "mysql" else "?"
    sql = f"SELECT * FROM users WHERE username={placeholder} AND password={placeholder}"
    cursor = conn.cursor()
    try:
        cursor.execute(sql, (username, password))
        user = cursor.fetchone()
    except (pymysql.Error, sqlite3.Error) as error:
        logger.error("database_error action=login user=%s error=%s", username, error)
        return "登录失败，请稍后重试", 500
    finally:
        cursor.close()
        conn.close()

    if user:
        login_attempts.pop(username, None)
        # 清除登录前会话内容并生成新的随机CSRF令牌，使Cookie值随登录变化。
        session.clear()
        session.permanent = True
        session["user"] = username
        session["csrf_token"] = secrets.token_hex(32)
        logger.info("login_success user=%s ip=%s", username, client_ip)
        return redirect(url_for("list_files"))

    record = login_attempts.setdefault(username, {"count": 0, "locked_until": None})
    record["count"] += 1
    if record["count"] >= 5:
        record["locked_until"] = now + timedelta(minutes=15)
        logger.warning("login_locked user=%s ip=%s", username, client_ip)
        return "连续失败5次，账号已锁定15分钟", 423
    return f"登录失败，用户名或密码错误，剩余尝试次数：{5 - record['count']}", 401


@app.route("/listfiles")
def list_files():
    if "user" not in session:
        return "请先登录", 401
    user_dir = current_user_directory()
    metadata = load_metadata(user_dir)
    files = []
    for path in user_dir.iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        info = metadata.get(path.name, {})
        files.append({
            "stored_name": path.name,
            "display_name": info.get("original_name", path.name),
            "size": path.stat().st_size,
        })
    files.sort(key=lambda item: item["display_name"].lower())
    return render_template(
        "filelist.html",
        username=session["user"],
        files=files,
        csrf_token=ensure_csrf_token(),
    )


@app.route("/upload", methods=["GET"])
def upload_page():
    if "user" not in session:
        return "请先登录", 401
    return render_template("upload.html", csrf_token=ensure_csrf_token())


@app.route("/upload", methods=["POST"])
def upload_file():
    if "user" not in session:
        return "未登录", 401
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "CSRF校验失败", 403

    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return "未选择文件", 400

    custom_name = request.form.get("customName", "").strip()
    original_name = custom_name or uploaded.filename
    safe_name = secure_filename(original_name)
    if not safe_name or len(safe_name) > 120 or "." not in safe_name:
        return "文件名不合法", 400
    extension = safe_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        logger.warning(
            "upload_rejected user=%s ip=%s name=%s reason=extension",
            session["user"], request.remote_addr, original_name,
        )
        return "不允许的文件类型，仅支持 txt、pdf、png、jpg、jpeg、zip", 415

    header = uploaded.stream.read(512)
    uploaded.stream.seek(0)
    detected_mime = detected_file_type(extension, header)
    if not detected_mime:
        logger.warning(
            "upload_rejected user=%s ip=%s name=%s reason=content_mismatch",
            session["user"], request.remote_addr, original_name,
        )
        return "文件内容与扩展名不匹配", 415

    stored_name = f"{uuid.uuid4().hex}.{extension}"
    user_dir = current_user_directory()
    save_path = user_dir / stored_name
    uploaded.save(save_path)

    metadata = load_metadata(user_dir)
    metadata[stored_name] = {
        "original_name": original_name,
        "size": save_path.stat().st_size,
        "detected_type": detected_mime,
        "uploaded_at": datetime.now().isoformat(timespec="seconds"),
    }
    save_metadata(user_dir, metadata)
    logger.info(
        "upload_allowed user=%s ip=%s original=%s stored=%s size=%s type=%s",
        session["user"], request.remote_addr, original_name, stored_name,
        save_path.stat().st_size, detected_mime,
    )
    return render_template("message.html", title="上传成功", message="文件已安全保存。", link="/listfiles")


@app.route("/download")
def download_file():
    if "user" not in session:
        return "未登录", 401
    stored_name = request.args.get("filename", "")
    user_dir, target = resolve_owned_file(stored_name)
    if not target.is_file():
        abort(404)
    metadata = load_metadata(user_dir)
    original_name = metadata.get(stored_name, {}).get("original_name", stored_name)
    logger.info("download user=%s stored=%s", session["user"], stored_name)
    return send_from_directory(
        str(user_dir),
        stored_name,
        as_attachment=True,
        download_name=original_name,
        mimetype="application/octet-stream",
    )


@app.route("/delete", methods=["POST"])
def delete_file():
    if "user" not in session:
        return "未登录", 401
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "CSRF校验失败", 403

    stored_name = request.form.get("filename", "")
    user_dir, target = resolve_owned_file(stored_name)
    if not target.is_file():
        return "文件不存在", 404
    target.unlink()
    metadata = load_metadata(user_dir)
    metadata.pop(stored_name, None)
    save_metadata(user_dir, metadata)
    logger.info("delete user=%s stored=%s", session["user"], stored_name)
    return redirect(url_for("list_files"))


@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "CSRF校验失败", 403
    user = session.get("user")
    session.clear()
    logger.info("logout user=%s", user)
    response = redirect(url_for("login_page"))
    response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return response


if __name__ == "__main__":
    app.run(debug=False)
