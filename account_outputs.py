"""负责账号结果、pending 恢复以及 grok2api token 池的安全持久化。"""
import json
import os
import tempfile
import time
from contextlib import ExitStack
from datetime import datetime, timezone

from filelock import FileLock


def append_account_line(path, email, password, sso):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{email}----{password}----{sso}\n")
        handle.flush()
        os.fsync(handle.fileno())


def save_mail_credential(base_dir, email, credential):
    path = os.path.join(base_dir, "mail_credentials.txt")
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{email}\t{credential}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return True


def queue_unsaved_account(path, payload, error):
    pending_path = path + ".pending.jsonl"
    record = dict(payload)
    record["save_error"] = str(error)
    record["queued_at"] = datetime.now(timezone.utc).isoformat()
    with open(pending_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.chmod(pending_path, 0o600)
    except Exception:
        pass
    return True


def _existing_account_keys(target_path):
    keys = set()
    if not os.path.isfile(target_path):
        return keys
    with open(target_path, "r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            parts = raw_line.rstrip("\n").split("----", 2)
            if len(parts) == 3:
                keys.add((parts[0].strip(), parts[2].strip()))
    return keys


def retry_pending_file(pending_path, output_path=None, log_callback=None):
    logger = log_callback or (lambda message: None)
    pending_path = os.path.realpath(os.path.abspath(os.path.expanduser(str(pending_path))))
    if not os.path.isfile(pending_path):
        raise FileNotFoundError(f"pending 文件不存在: {pending_path}")
    suffix = ".pending.jsonl"
    if output_path:
        target_path = os.path.realpath(os.path.abspath(os.path.expanduser(str(output_path))))
    elif pending_path.endswith(suffix):
        target_path = os.path.realpath(pending_path[:-len(suffix)])
    else:
        target_path = os.path.realpath(pending_path + ".recovered.txt")
    if os.path.normcase(pending_path) == os.path.normcase(target_path):
        raise ValueError("pending 输入文件与输出文件不能是同一个文件")

    lock_paths = sorted(
        {pending_path + ".lock", target_path + ".lock"},
        key=lambda value: os.path.normcase(os.path.abspath(value)),
    )
    with ExitStack() as stack:
        for lock_path in lock_paths:
            stack.enter_context(FileLock(lock_path, timeout=30))
        if not os.path.isfile(pending_path):
            return {"restored": 0, "remaining": 0, "output_path": target_path}
        with open(pending_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        existing = _existing_account_keys(target_path)
        unresolved = []
        restored = 0
        for line_number, raw_line in enumerate(lines, 1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
                if not isinstance(record, dict):
                    raise ValueError("record must be a JSON object")
                email = str(record.get("email") or "").strip()
                password = str(record.get("password") or "")
                sso = str(record.get("sso") or "").strip()
                if not email or not sso:
                    raise ValueError("record missing email or sso")
                key = (email, sso)
                if key not in existing:
                    append_account_line(target_path, email, password, sso)
                    existing.add(key)
                restored += 1
                logger(f"[+] 已恢复 pending 账号: {email}")
            except Exception as exc:
                unresolved.append(raw_line if raw_line.endswith("\n") else raw_line + "\n")
                logger(f"[!] pending 第 {line_number} 行恢复失败: {exc}")

        directory = os.path.dirname(pending_path) or "."
        fd, temp_path = tempfile.mkstemp(prefix=".pending-retry-", suffix=".jsonl.tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.writelines(unresolved)
                handle.flush()
                os.fsync(handle.fileno())
            if unresolved:
                os.replace(temp_path, pending_path)
                temp_path = None
                try:
                    os.chmod(pending_path, 0o600)
                except Exception:
                    pass
            else:
                os.unlink(temp_path)
                temp_path = None
                try:
                    os.unlink(pending_path)
                except FileNotFoundError:
                    pass
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
        return {"restored": restored, "remaining": len(unresolved), "output_path": target_path}


# Token-pool runtime dependencies are injected by the application adapter.
config = {}
_http_get = None
_http_post = None
_log_exception = None
_remote_compat_error = RuntimeError
_remote_request_error = RuntimeError
_admin_v1_access_token = ""
_admin_v1_access_expires_at = 0.0


def configure_token_runtime(config_ref, http_get, http_post, log_exception,
                            compatibility_error=RuntimeError, request_error=RuntimeError):
    global config, _http_get, _http_post, _log_exception
    global _remote_compat_error, _remote_request_error
    global _admin_v1_access_token, _admin_v1_access_expires_at
    config = config_ref
    _http_get = http_get
    _http_post = http_post
    _log_exception = log_exception
    _remote_compat_error = compatibility_error
    _remote_request_error = request_error
    _admin_v1_access_token = ""
    _admin_v1_access_expires_at = 0.0
    globals()["http_get"] = http_get
    globals()["http_post"] = http_post
    globals()["log_exception"] = log_exception
    globals()["RemoteTokenCompatibilityError"] = compatibility_error
    globals()["RemoteTokenRequestError"] = request_error


def resolve_grok2api_local_token_file():
    configured = str(config.get("grok2api_local_token_file", "") or "").strip()
    if configured:
        return configured
    return os.path.join(os.path.dirname(__file__), "token.json")

def _normalize_sso_token(raw_token):
    token = str(raw_token or "").strip()
    if token.startswith("sso="):
        token = token[4:]
    return token


def _normalize_remote_base(base):
    return str(base or "").strip().rstrip("/")


def _parse_sse_events(text):
    """解析 text/event-stream，返回 (complete_data, error_data)。"""
    complete = None
    error = None
    event_name = None
    data_lines = []

    def flush():
        nonlocal complete, error, event_name, data_lines
        if event_name is None and not data_lines:
            return
        payload_text = "\n".join(data_lines).strip()
        payload = None
        if payload_text:
            try:
                payload = json.loads(payload_text)
            except Exception:
                payload = {"raw": payload_text}
        if event_name == "complete":
            complete = payload if isinstance(payload, dict) else {"raw": payload}
        elif event_name == "error":
            error = payload if isinstance(payload, dict) else {"message": str(payload)}
        event_name = None
        data_lines = []

    for raw_line in str(text or "").splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            flush()
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[6:].strip()
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
            continue
    flush()
    return complete, error


def _build_multipart_files_body(filename, content, content_type="text/plain"):
    boundary = f"----grokregister{int(time.time() * 1000)}{os.getpid()}"
    filename = str(filename or "grok-web-sso-tokens.txt")
    payload = content if isinstance(content, (bytes, bytearray)) else str(content or "").encode("utf-8")
    chunks = [
        f"--{boundary}\r\n".encode("ascii"),
        (
            f'Content-Disposition: form-data; name="files"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode("utf-8"),
        payload,
        b"\r\n",
        f"--{boundary}--\r\n".encode("ascii"),
    ]
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _admin_v1_login(base, password, username="admin"):
    global _admin_v1_access_token, _admin_v1_access_expires_at
    now = time.time()
    if _admin_v1_access_token and _admin_v1_access_expires_at - 30 > now:
        return _admin_v1_access_token

    endpoint = f"{base}/api/admin/v1/auth/login"
    try:
        response = http_post(
            endpoint,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"username": str(username or "admin"), "password": str(password or "")},
            timeout=20,
        )
    except Exception as exc:
        raise RemoteTokenRequestError(f"新版管理登录网络失败: {endpoint}: {exc}") from exc

    status = int(getattr(response, "status_code", 0) or 0)
    body = str(getattr(response, "text", "") or "")
    if status in (404, 405):
        raise RemoteTokenCompatibilityError(f"新版管理登录接口不可用: {endpoint}: HTTP {status}")
    if not 200 <= status < 300:
        raise RemoteTokenRequestError(f"新版管理登录失败: {endpoint}: HTTP {status}: {body[:300]}")

    try:
        payload = response.json()
    except Exception as exc:
        raise RemoteTokenRequestError(f"新版管理登录响应非 JSON: {endpoint}: {exc}") from exc

    data = payload.get("data") if isinstance(payload, dict) else None
    tokens = data.get("tokens") if isinstance(data, dict) else None
    access = ""
    if isinstance(tokens, dict):
        access = str(tokens.get("accessToken") or "").strip()
    if not access:
        raise RemoteTokenRequestError(f"新版管理登录未返回 accessToken: {endpoint}")

    expires_at = now + 12 * 60
    expires_raw = ""
    if isinstance(tokens, dict):
        expires_raw = str(tokens.get("accessTokenExpiresAt") or "").strip()
    if expires_raw:
        try:
            # 兼容 "2026-..." ISO 字符串；失败则沿用默认 12 分钟缓存
            from datetime import datetime

            parsed = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
            expires_at = parsed.timestamp()
        except Exception:
            pass

    _admin_v1_access_token = access
    _admin_v1_access_expires_at = expires_at
    return access


def _admin_v1_auth_headers(access_token, content_type=None, accept="application/json"):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": accept,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _admin_v1_import_web_sso(base, access_token, token, email=""):
    endpoint = f"{base}/api/admin/v1/accounts/web/import"
    # 与后台“快速导入 SSO”一致：纯 token 文本即可
    file_body = token
    body, content_type = _build_multipart_files_body(
        "grok-web-sso-tokens.txt",
        file_body,
        content_type="text/plain",
    )
    headers = _admin_v1_auth_headers(access_token, content_type=content_type, accept="text/event-stream")
    try:
        response = http_post(endpoint, headers=headers, data=body, timeout=90)
        status = int(getattr(response, "status_code", 0) or 0)
        text = str(getattr(response, "text", "") or "")
    except Exception as exc:
        # curl_cffi 在 SSE 结束时偶发 IncompleteRead，尽量从 partial response 恢复
        partial = getattr(exc, "response", None)
        if partial is not None:
            status = int(getattr(partial, "status_code", 0) or 0)
            text = str(getattr(partial, "text", "") or "")
            if 200 <= status < 300 and text:
                complete, error = _parse_sse_events(text)
                if isinstance(complete, dict):
                    created = int(complete.get("created") or 0)
                    updated = int(complete.get("updated") or 0)
                    skipped = int(complete.get("skipped") or 0)
                    if created + updated + skipped > 0 and not error:
                        return complete
        raise RemoteTokenRequestError(f"新版 Web 导入网络失败: {endpoint}: {exc}") from exc

    if status in (404, 405):
        raise RemoteTokenCompatibilityError(f"新版 Web 导入接口不可用: {endpoint}: HTTP {status}")
    if status == 401:
        raise RemoteTokenRequestError(f"新版 Web 导入未授权: {endpoint}: HTTP 401")
    if not 200 <= status < 300:
        raise RemoteTokenRequestError(f"新版 Web 导入失败: {endpoint}: HTTP {status}: {text[:300]}")

    complete, error = _parse_sse_events(text)
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise RemoteTokenRequestError(f"新版 Web 导入 SSE error: {code or ''}: {message}")
    if not isinstance(complete, dict):
        raise RemoteTokenRequestError(f"新版 Web 导入未返回 complete 事件: {endpoint}")

    created = int(complete.get("created") or 0)
    updated = int(complete.get("updated") or 0)
    skipped = int(complete.get("skipped") or 0)
    if created + updated + skipped <= 0:
        raise RemoteTokenRequestError(
            f"新版 Web 导入 complete 无有效结果: created={created} updated={updated} skipped={skipped}"
        )
    return complete


def _admin_v1_find_web_account_id(base, access_token, email=""):
    email = str(email or "").strip()
    if not email:
        return None
    endpoint = f"{base}/api/admin/v1/accounts"
    headers = _admin_v1_auth_headers(access_token)
    params = {
        "provider": "grok_web",
        "page": 1,
        "pageSize": 20,
        "search": email,
        "sortBy": "createdAt",
        "sortOrder": "desc",
    }
    try:
        response = http_get(endpoint, headers=headers, params=params, timeout=20)
    except Exception as exc:
        raise RemoteTokenRequestError(f"查询 Web 账号网络失败: {endpoint}: {exc}") from exc

    status = int(getattr(response, "status_code", 0) or 0)
    if status != 200:
        body = str(getattr(response, "text", "") or "")[:300]
        raise RemoteTokenRequestError(f"查询 Web 账号失败: {endpoint}: HTTP {status}: {body}")

    try:
        payload = response.json()
    except Exception as exc:
        raise RemoteTokenRequestError(f"查询 Web 账号响应非 JSON: {exc}") from exc

    data = payload.get("data") if isinstance(payload, dict) else None
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None

    email_l = email.lower()
    for item in items:
        if not isinstance(item, dict):
            continue
        item_email = str(item.get("email") or "").strip().lower()
        if item_email == email_l:
            account_id = str(item.get("id") or "").strip()
            if account_id:
                return account_id
    # 模糊匹配：列表已按 search 过滤时取第一条
    for item in items:
        if isinstance(item, dict) and str(item.get("id") or "").strip():
            return str(item.get("id")).strip()
    return None


def _admin_v1_convert_web_to_build(base, access_token, account_id, strategy="missing"):
    endpoint = f"{base}/api/admin/v1/accounts/web/convert-to-build"
    headers = _admin_v1_auth_headers(
        access_token,
        content_type="application/json",
        accept="text/event-stream",
    )
    body = {
        "ids": [str(account_id)],
        "strategy": str(strategy or "missing"),
    }
    try:
        response = http_post(endpoint, headers=headers, json=body, timeout=120)
        status = int(getattr(response, "status_code", 0) or 0)
        text = str(getattr(response, "text", "") or "")
    except Exception as exc:
        partial = getattr(exc, "response", None)
        if partial is not None:
            status = int(getattr(partial, "status_code", 0) or 0)
            text = str(getattr(partial, "text", "") or "")
            if 200 <= status < 300 and text:
                complete, error = _parse_sse_events(text)
                if isinstance(complete, dict) and not error:
                    return complete
        raise RemoteTokenRequestError(f"Web 转 Build 网络失败: {endpoint}: {exc}") from exc

    if not 200 <= status < 300:
        raise RemoteTokenRequestError(f"Web 转 Build 失败: {endpoint}: HTTP {status}: {text[:300]}")

    complete, error = _parse_sse_events(text)
    if error:
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise RemoteTokenRequestError(f"Web 转 Build SSE error: {code or ''}: {message}")
    if not isinstance(complete, dict):
        raise RemoteTokenRequestError(f"Web 转 Build 未返回 complete 事件: {endpoint}")
    return complete


def add_token_to_grok2api_remote_pool_admin_v1(raw_token, email="", log_callback=None):
    """新版 grok2api：JWT 登录 + Web SSO 导入 + 可选 convert-to-build。"""
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    base = _normalize_remote_base(config.get("grok2api_remote_base", ""))
    app_key = str(config.get("grok2api_remote_app_key", "") or "").strip()
    username = str(config.get("grok2api_remote_admin_username", "admin") or "admin").strip() or "admin"
    if not base or not app_key:
        raise RemoteTokenRequestError("grok2api 远端未配置 base/app_key")

    access = _admin_v1_login(base, app_key, username=username)
    import_result = _admin_v1_import_web_sso(base, access, token, email=email)
    if log_callback:
        log_callback(
            "[+] 已写入 grok2api 远端 Web 账号: "
            f"created={import_result.get('created', 0)} "
            f"updated={import_result.get('updated', 0)} "
            f"skipped={import_result.get('skipped', 0)} "
            f"({base}/api/admin/v1/accounts/web/import)"
        )

    auto_convert = bool(config.get("grok2api_auto_convert_to_build", True))
    if not auto_convert:
        return True

    try:
        account_id = _admin_v1_find_web_account_id(base, access, email=email)
        if not account_id:
            if log_callback:
                log_callback("[!] Web 导入成功，但未定位到账号 ID，跳过 convert-to-build")
            return True

        strategy = str(config.get("grok2api_convert_strategy", "missing") or "missing").strip() or "missing"
        convert_result = _admin_v1_convert_web_to_build(base, access, account_id, strategy=strategy)
        created = int(convert_result.get("created") or 0)
        linked = int(convert_result.get("linked") or 0)
        skipped = int(convert_result.get("skipped") or 0)
        failed = int(convert_result.get("failed") or 0)
        if log_callback:
            log_callback(
                f"[+] Web 转 Build 完成: id={account_id} "
                f"created={created} linked={linked} skipped={skipped} failed={failed} strategy={strategy}"
            )
        if failed > 0 and created + linked <= 0 and log_callback:
            log_callback(
                f"[!] Web 转 Build 未成功（Web 账号已导入）: id={account_id} failed={failed}"
            )
    except Exception as exc:
        # 导入已成功；转换失败只告警，不回滚入池结果
        if log_callback:
            log_callback(f"[!] Web 转 Build 异常（Web 账号已导入）: {exc}")
    return True

def add_token_to_grok2api_local_pool(raw_token, email="", log_callback=None):
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    token_file = os.path.abspath(resolve_grok2api_local_token_file())
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip() or "ssoBasic"
    parent = os.path.dirname(token_file)
    os.makedirs(parent, exist_ok=True)
    lock_path = token_file + ".lock"
    try:
        with open(lock_path, "a", encoding="utf-8"):
            pass
        os.chmod(lock_path, 0o600)
    except Exception:
        pass
    try:
        from filelock import FileLock
    except Exception as exc:
        raise RuntimeError(f"filelock 依赖不可用，拒绝非原子写入 token 池: {exc}")
    with FileLock(lock_path, timeout=30):
        data = {}
        if os.path.exists(token_file):
            try:
                with open(token_file, "r", encoding="utf-8") as f:
                    data = json.load(f) or {}
            except Exception as exc:
                broken_path = token_file + f".broken-{int(time.time())}"
                try:
                    os.replace(token_file, broken_path)
                except Exception:
                    broken_path = token_file
                raise RuntimeError(f"本地 token 文件 JSON 解析失败，已停止写入以避免覆盖: {broken_path}: {exc}")
        if not isinstance(data, dict):
            raise RuntimeError("本地 token 文件根节点不是 JSON object，拒绝覆盖")
        pool = data.get(pool_name)
        if pool is None:
            pool = []
        elif not isinstance(pool, list):
            raise RuntimeError(f"本地 token 池 {pool_name} 不是列表，拒绝覆盖")
        existing = set()
        for item in pool:
            if isinstance(item, str):
                existing.add(_normalize_sso_token(item))
            elif isinstance(item, dict):
                existing.add(_normalize_sso_token(item.get("token", "")))
        if token in existing:
            if log_callback:
                log_callback(f"[*] grok2api 本地池已存在 token: {pool_name}")
            return True
        pool.append({"token": token, "tags": ["auto-register"], "note": email})
        data[pool_name] = pool
        if os.path.exists(token_file):
            backup_path = token_file + ".bak"
            try:
                with open(token_file, "rb") as src, open(backup_path, "wb") as dst:
                    dst.write(src.read())
                    dst.flush()
                    os.fsync(dst.fileno())
                try:
                    os.chmod(backup_path, 0o600)
                except Exception:
                    pass
            except Exception as exc:
                raise RuntimeError(f"创建本地 token 备份失败，拒绝继续写入: {exc}")
        fd, temp_path = tempfile.mkstemp(prefix=".token-", suffix=".tmp", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(temp_path, 0o600)
            except Exception:
                pass
            os.replace(temp_path, token_file)
            temp_path = None
            try:
                os.chmod(token_file, 0o600)
            except Exception:
                pass
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 本地池: {pool_name} ({token_file})")
    return True

def get_grok2api_remote_api_bases(base):
    """生成 grok2api 管理 API 候选根路径。

    参数:
      - base str: 用户配置的 grok2api 远端地址

    返回:
      - list[str]: 依次尝试的管理 API 根路径
    """
    normalized = str(base or "").strip().rstrip("/")
    if not normalized:
        return []
    lower = normalized.lower()
    candidates = [normalized]
    if lower.endswith("/admin/api"):
        return candidates
    if lower.endswith("/admin"):
        candidates.append(f"{normalized}/api")
    else:
        candidates.append(f"{normalized}/admin/api")
    seen = set()
    unique = []
    for item in candidates:
        if item not in seen:
            unique.append(item)
            seen.add(item)
    return unique

def add_token_to_grok2api_remote_pool_legacy(raw_token, email="", log_callback=None):
    """旧版 grok2api：/tokens/add?app_key=... 或可选全量保存。"""
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    base = _normalize_remote_base(config.get("grok2api_remote_base", ""))
    app_key = str(config.get("grok2api_remote_app_key", "") or "").strip()
    pool_name = str(config.get("grok2api_pool_name", "ssoBasic") or "ssoBasic").strip()
    if not base or not app_key:
        raise RemoteTokenRequestError("grok2api 远端未配置 base/app_key")
    headers = {"Content-Type": "application/json"}
    query = {"app_key": app_key}
    remote_pool = {"ssoBasic": "basic", "ssoSuper": "super"}[pool_name]
    api_bases = get_grok2api_remote_api_bases(base)
    incompatible = []
    add_payload = {"tokens": [token], "pool": remote_pool, "tags": ["auto-register"]}
    for api_base in api_bases:
        endpoint = f"{api_base}/tokens/add"
        try:
            response = http_post(endpoint, headers=headers, params=query, json=add_payload, timeout=30)
        except Exception as exc:
            raise RemoteTokenRequestError(f"远端 /tokens/add 网络请求失败: {endpoint}: {exc}") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if 200 <= status < 300:
            if log_callback:
                log_callback(f"[+] 已写入 grok2api 远端池: {pool_name} ({endpoint})")
            return True
        if status in (404, 405):
            incompatible.append(f"{endpoint}: HTTP {status}")
            continue
        body = str(getattr(response, "text", "") or "")[:300]
        raise RemoteTokenRequestError(f"远端 /tokens/add 请求失败，不允许全量回退: {endpoint}: HTTP {status}: {body}")
    if not bool(config.get("grok2api_allow_legacy_full_save", False)):
        raise RemoteTokenCompatibilityError(
            "/tokens/add 不受支持，旧版全量保存默认禁用以避免并发覆盖: " + "; ".join(incompatible)
        )
    current = None
    fallback_base = None
    etag = None
    load_errors = []
    for api_base in api_bases or [base]:
        endpoint = f"{api_base}/tokens"
        try:
            response = http_get(endpoint, headers=headers, params=query, timeout=20)
        except Exception as exc:
            raise RemoteTokenRequestError(f"旧版远端池读取网络失败: {endpoint}: {exc}") from exc
        status = int(getattr(response, "status_code", 0) or 0)
        if status != 200:
            load_errors.append(f"{endpoint}: HTTP {status}")
            continue
        payload = response.json()
        candidate = payload.get("tokens") if isinstance(payload, dict) and "tokens" in payload else payload
        if not isinstance(candidate, dict):
            load_errors.append(f"{endpoint}: unexpected payload")
            continue
        current = candidate
        fallback_base = api_base
        response_headers = getattr(response, "headers", {}) or {}
        etag = response_headers.get("ETag") or response_headers.get("etag")
        break
    if current is None or fallback_base is None:
        raise RemoteTokenRequestError("无法安全读取旧版远端 token 池: " + "; ".join(load_errors))
    pool = current.get(pool_name)
    if pool is None:
        pool = []
    elif not isinstance(pool, list):
        raise RemoteTokenRequestError(f"远端 token 池 {pool_name} 不是列表，拒绝全量覆盖")
    existing = {
        _normalize_sso_token(item if isinstance(item, str) else item.get("token", ""))
        for item in pool if isinstance(item, (str, dict))
    }
    if token not in existing:
        pool.append({"token": token, "tags": ["auto-register"], "note": email})
    current[pool_name] = pool
    if not etag:
        raise RemoteTokenCompatibilityError(
            "旧版远端接口未提供 ETag，无法保证并发安全，已拒绝全量保存"
        )
    save_headers = dict(headers)
    save_headers["If-Match"] = etag
    endpoint = f"{fallback_base}/tokens"
    try:
        response = http_post(endpoint, headers=save_headers, params=query, json=current, timeout=30)
    except Exception as exc:
        raise RemoteTokenRequestError(f"旧版远端池保存网络失败: {endpoint}: {exc}") from exc
    status = int(getattr(response, "status_code", 0) or 0)
    if not 200 <= status < 300:
        raise RemoteTokenRequestError(f"旧版远端池保存失败: {endpoint}: HTTP {status}")
    if log_callback:
        log_callback(f"[+] 已写入 grok2api 远端池（旧版兼容）: {pool_name} ({endpoint})")
    return True


def add_token_to_grok2api_remote_pool(raw_token, email="", log_callback=None):
    """优先新版 /api/admin/v1，失败再回退旧版 /tokens/add。"""
    token = _normalize_sso_token(raw_token)
    if not token:
        return False
    base = _normalize_remote_base(config.get("grok2api_remote_base", ""))
    app_key = str(config.get("grok2api_remote_app_key", "") or "").strip()
    if not base or not app_key:
        raise RemoteTokenRequestError("grok2api 远端未配置 base/app_key")

    try:
        return add_token_to_grok2api_remote_pool_admin_v1(raw_token, email=email, log_callback=log_callback)
    except Exception as admin_exc:
        # 仅在新版接口“不存在”时回退旧版；鉴权/业务错误直接抛出
        is_compat = isinstance(admin_exc, _remote_compat_error) or (
            admin_exc.__class__.__name__ == "RemoteTokenCompatibilityError"
        )
        if is_compat:
            if log_callback:
                log_callback(f"[*] 新版管理 API 不可用，回退旧版 token 池: {admin_exc}")
            return add_token_to_grok2api_remote_pool_legacy(raw_token, email=email, log_callback=log_callback)
        raise


def add_token_to_grok2api_pools(raw_token, email="", log_callback=None):
    result = {
        "local": {"enabled": bool(config.get("grok2api_auto_add_local", False)), "ok": None, "error": None},
        "remote": {"enabled": bool(config.get("grok2api_auto_add_remote", False)), "ok": None, "error": None},
    }
    if result["local"]["enabled"]:
        try:
            result["local"]["ok"] = bool(add_token_to_grok2api_local_pool(raw_token, email=email, log_callback=log_callback))
        except Exception as exc:
            result["local"]["ok"] = False
            result["local"]["error"] = log_exception("写入 grok2api 本地池失败", exc, log_callback)
    if result["remote"]["enabled"]:
        try:
            result["remote"]["ok"] = bool(add_token_to_grok2api_remote_pool(raw_token, email=email, log_callback=log_callback))
        except Exception as exc:
            result["remote"]["ok"] = False
            result["remote"]["error"] = log_exception("写入 grok2api 远端池失败", exc, log_callback)
    return result

