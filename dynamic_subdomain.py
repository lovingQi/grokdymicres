"""每账号动态创建 / 拆除 Cloudflare temp-email 子域。"""

from __future__ import annotations

import json
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

CF_API = "https://api.cloudflare.com/client/v4"
FIXED_ROOT = "xbltest.xyz"

RESERVED_LABELS = {
    "www",
    "ftp",
    "api",
    "mail",
    "admin",
    "root",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "pop",
    "imap",
    "webmail",
    "cdn",
    "static",
    "dev",
    "test",
    "staging",
    "prod",
    "app",
    "blog",
    "shop",
    "vpn",
    "git",
    "ssh",
    "portal",
    "status",
    "docs",
}

LogFn = Optional[Callable[[str], None]]


@dataclass
class ProvisionResult:
    ok: bool
    domain: str = ""
    error: str = ""
    domains_json: str = ""


def mask_token(token: str) -> str:
    token = str(token or "")
    if len(token) <= 8:
        return "****"
    return f"...{token[-4:]}"


def _log(log: LogFn, message: str) -> None:
    if log:
        log(message)


def parse_keep_domains(value: str, root: str = FIXED_ROOT) -> List[str]:
    items = [x.strip().lower() for x in str(value or "").split(",") if x.strip()]
    if not items:
        items = [f"mail.{root}"]
    return items


def generate_subdomain(
    root: str = FIXED_ROOT,
    *,
    exclude_labels: Optional[set] = None,
    min_len: int = 10,
    max_len: int = 14,
) -> str:
    """
    生成更随机的子域标签：
    - 默认 10–14 位（不再是 3–4 位）
    - 字母 + 数字，首字符必须是字母（DNS 更稳妥）
    - 使用 secrets（密码学随机）而非 random
    """
    root = (root or FIXED_ROOT).strip().lower()
    min_len = max(6, int(min_len))
    max_len = max(min_len, int(max_len))
    max_len = min(max_len, 48)  # DNS label 上限 63，留余量
    blocked = set(RESERVED_LABELS)
    if exclude_labels:
        for item in exclude_labels:
            item = str(item).strip().lower()
            if not item:
                continue
            blocked.add(item.split(".")[0])
    alphabet_start = string.ascii_lowercase
    alphabet_rest = string.ascii_lowercase + string.digits
    for _ in range(2000):
        n = secrets.randbelow(max_len - min_len + 1) + min_len
        label = secrets.choice(alphabet_start) + "".join(
            secrets.choice(alphabet_rest) for _ in range(n - 1)
        )
        if label in blocked:
            continue
        return f"{label}.{root}"
    raise RuntimeError("无法生成可用子域标签")


def _cf_request(
    token: str,
    method: str,
    path: str,
    body: Any = None,
    query: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    url = f"{CF_API}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {"success": True, "result": None}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
        except json.JSONDecodeError:
            parsed = {"success": False, "errors": [{"message": err_body}]}
        parsed["_http_status"] = exc.code
        return parsed
    except urllib.error.URLError as exc:
        return {"success": False, "errors": [{"message": str(exc.reason)}]}


def _error_message(payload: Dict[str, Any]) -> str:
    errors = payload.get("errors") or []
    if errors and isinstance(errors[0], dict):
        return str(errors[0].get("message") or errors[0])
    if payload.get("_http_status"):
        return f"HTTP {payload['_http_status']}"
    return str(payload)


def get_zone_id(token: str, root: str, zone_id: str = "") -> str:
    if zone_id:
        return zone_id
    res = _cf_request(token, "GET", "/zones", query={"name": root})
    if not res.get("success"):
        raise RuntimeError(f"查询 zone 失败: {_error_message(res)}")
    results = res.get("result") or []
    if not results:
        raise RuntimeError(f"未找到域名 zone: {root}")
    return str(results[0].get("id") or "")


def get_account_id(token: str, zone_id: str, account_id: str = "") -> str:
    if account_id:
        return account_id
    res = _cf_request(token, "GET", f"/zones/{zone_id}")
    if not res.get("success"):
        raise RuntimeError(f"查询 account 失败: {_error_message(res)}")
    account = (res.get("result") or {}).get("account") or {}
    aid = account.get("id")
    if not aid:
        raise RuntimeError("zone 响应中缺少 account.id")
    return str(aid)


def parse_domains_json(value: str) -> List[str]:
    value = (value or "").strip()
    if not value:
        return []
    try:
        data = json.loads(value)
        if isinstance(data, list):
            return [str(x).strip().lower() for x in data if str(x).strip()]
    except json.JSONDecodeError:
        pass
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def domains_to_json(domains: List[str]) -> str:
    return json.dumps(domains, ensure_ascii=False, separators=(",", ":"))


def merge_domains(
    existing: List[str],
    *,
    add: Optional[List[str]] = None,
    remove: Optional[List[str]] = None,
) -> List[str]:
    rem = {x.strip().lower() for x in (remove or []) if x.strip()}
    out: List[str] = []
    seen = set()
    for item in list(existing) + list(add or []):
        d = str(item).strip().lower()
        if not d or d in rem or d in seen:
            continue
        seen.add(d)
        out.append(d)
    return out


def _binding_domain_value(binding: Dict[str, Any]) -> str:
    """从单个 binding 提取可被 parse_domains_json 解析的字符串。"""
    btype = str(binding.get("type") or "")
    if btype == "json":
        raw = binding.get("json")
        if isinstance(raw, list):
            return json.dumps(raw, ensure_ascii=False)
        if raw is None:
            return ""
        return str(raw)
    if "text" in binding:
        return str(binding.get("text") or "")
    if "value" in binding:
        return str(binding.get("value") or "")
    return ""


def _extract_domain_vars(settings: Dict[str, Any]) -> Dict[str, str]:
    """读取 Worker 上的 DOMAINS / DEFAULT_DOMAINS（支持 plain_text 与 json）。"""
    result = settings.get("result") or {}
    out: Dict[str, str] = {}
    bindings = result.get("bindings")
    if isinstance(bindings, list):
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            name = binding.get("name")
            if name not in ("DOMAINS", "DEFAULT_DOMAINS"):
                continue
            out[str(name)] = _binding_domain_value(binding)
    vars_obj = result.get("vars") or result.get("environment_variables")
    if isinstance(vars_obj, dict):
        for key in ("DOMAINS", "DEFAULT_DOMAINS"):
            if key in out:
                continue
            if key not in vars_obj:
                continue
            value = vars_obj[key]
            if isinstance(value, dict) and "value" in value:
                out[key] = str(value["value"])
            elif isinstance(value, list):
                out[key] = json.dumps(value, ensure_ascii=False)
            else:
                out[key] = str(value)
    return out


# 兼容旧名
def _extract_plain_text_vars(settings: Dict[str, Any]) -> Dict[str, str]:
    return _extract_domain_vars(settings)


def _detect_domains_binding_type(bindings: Optional[List[dict]]) -> str:
    """优先沿用现有 DOMAINS 绑定类型；默认 json（cloudflare_temp_email 常见）。"""
    for binding in bindings or []:
        if not isinstance(binding, dict):
            continue
        if binding.get("name") not in ("DOMAINS", "DEFAULT_DOMAINS"):
            continue
        btype = str(binding.get("type") or "").strip()
        if btype in ("json", "plain_text", "text"):
            return "json" if btype == "json" else "plain_text"
    return "json"


def _sanitize_binding_for_rewrite(binding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    将 GET settings 返回的 binding 规范化为可安全 PATCH 回写的形态。

    关键规则：
    - secret_text：只回传 name+type，不带 text（CF 会保留原 secret 值）
    - d1：只回传 name + database_id
    - 绝不在「不完整 bindings 列表」上成功写入
    """
    if not isinstance(binding, dict):
        return None
    name = str(binding.get("name") or "").strip()
    btype = str(binding.get("type") or "").strip()
    if not name or not btype:
        return None
    if name in ("DOMAINS", "DEFAULT_DOMAINS"):
        return None

    if btype == "secret_text":
        # 无 text 时 PATCH 会继承已有 secret，不会清空
        return {"type": "secret_text", "name": name}

    if btype == "d1":
        item: Dict[str, Any] = {"type": "d1", "name": name}
        db_id = binding.get("database_id") or binding.get("id")
        if not db_id:
            return None
        item["database_id"] = str(db_id)
        return item

    if btype == "json":
        item = {"type": "json", "name": name}
        if "json" in binding:
            item["json"] = binding["json"]
        return item

    if btype in ("plain_text", "text"):
        item = {"type": "plain_text", "name": name}
        if "text" in binding:
            item["text"] = str(binding.get("text") or "")
        elif "value" in binding:
            item["text"] = str(binding.get("value") or "")
        return item

    if btype == "kv_namespace":
        item = {"type": "kv_namespace", "name": name}
        ns = binding.get("namespace_id") or binding.get("id")
        if not ns:
            return None
        item["namespace_id"] = str(ns)
        return item

    if btype == "r2_bucket":
        item = {"type": "r2_bucket", "name": name}
        bucket = binding.get("bucket_name")
        if not bucket:
            return None
        item["bucket_name"] = str(bucket)
        return item

    # 未知类型：去掉敏感字段后尽量原样保留，避免误删
    unsafe_keys = {
        "text",
        "value",
        "secret",
        "secret_text",
        "key_base64",
        "key_jwk",
        "private_key",
    }
    item = {k: v for k, v in binding.items() if k not in unsafe_keys}
    if "name" not in item or "type" not in item:
        return None
    return item


def _build_domains_bindings(
    domains: List[str],
    *,
    domains_type: str = "json",
    include_default: bool = True,
) -> List[Dict[str, Any]]:
    cleaned = [str(x).strip().lower() for x in domains if str(x).strip()]
    out: List[Dict[str, Any]] = []
    if domains_type == "plain_text":
        payload = domains_to_json(cleaned)
        out.append({"type": "plain_text", "name": "DOMAINS", "text": payload})
        if include_default:
            out.append({"type": "plain_text", "name": "DEFAULT_DOMAINS", "text": payload})
    else:
        out.append({"type": "json", "name": "DOMAINS", "json": cleaned})
        if include_default:
            out.append({"type": "json", "name": "DEFAULT_DOMAINS", "json": cleaned})
    return out


def read_worker_domains(
    token: str, account_id: str, worker_name: str
) -> Dict[str, Any]:
    settings = _cf_request(
        token, "GET", f"/accounts/{account_id}/workers/scripts/{worker_name}/settings"
    )
    if not settings.get("success"):
        return {"ok": False, "domains": [], "bindings": [], "error": _error_message(settings)}
    vars_map = _extract_domain_vars(settings)
    domains = parse_domains_json(vars_map.get("DOMAINS", ""))
    if not domains:
        domains = parse_domains_json(vars_map.get("DEFAULT_DOMAINS", ""))
    bindings = (settings.get("result") or {}).get("bindings") or []
    if not isinstance(bindings, list):
        bindings = []
    return {
        "ok": True,
        "domains": domains,
        "bindings": bindings,
        "raw_vars": vars_map,
        "domains_binding_type": _detect_domains_binding_type(bindings),
    }


def _cf_multipart_patch_settings(
    token: str, account_id: str, worker_name: str, settings_obj: Dict[str, Any]
) -> Dict[str, Any]:
    """Workers settings PATCH 要求 multipart/form-data，settings 为 JSON part。"""
    import uuid

    boundary = f"----GrokRegisterBoundary{uuid.uuid4().hex}"
    settings_json = json.dumps(settings_obj, ensure_ascii=False)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="settings"\r\n'
        f"Content-Type: application/json\r\n\r\n"
        f"{settings_json}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    url = f"{CF_API}/accounts/{account_id}/workers/scripts/{worker_name}/settings"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {"success": True, "result": None}
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
        except json.JSONDecodeError:
            parsed = {"success": False, "errors": [{"message": err_body}]}
        parsed["_http_status"] = exc.code
        return parsed
    except urllib.error.URLError as exc:
        return {"success": False, "errors": [{"message": str(exc.reason)}]}


def write_worker_domains(
    token: str,
    account_id: str,
    worker_name: str,
    domains: List[str],
    existing_bindings: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """
    更新 Worker 的 DOMAINS，同时完整保留 JWT_SECRET / D1 / 其它 bindings。

    禁止「只写 DOMAINS 两个变量」的危险回退：Cloudflare settings bindings
    是整表替换，不完整列表会删掉 JWT_SECRET、DB 等。
    """
    payload = domains_to_json(domains)
    source_bindings = existing_bindings
    if source_bindings is None:
        current = read_worker_domains(token, account_id, worker_name)
        if not current.get("ok"):
            return {
                "ok": False,
                "domains_json": payload,
                "error": f"写入前读取 bindings 失败: {current.get('error')}",
            }
        source_bindings = current.get("bindings") or []

    preserved: List[Dict[str, Any]] = []
    dropped: List[str] = []
    for binding in source_bindings or []:
        if not isinstance(binding, dict):
            continue
        name = str(binding.get("name") or "")
        if name in ("DOMAINS", "DEFAULT_DOMAINS"):
            continue
        sanitized = _sanitize_binding_for_rewrite(binding)
        if sanitized is None:
            dropped.append(f"{name}:{binding.get('type')}")
            continue
        preserved.append(sanitized)

    # 关键保护：原有 secret_text / d1 若 sanitize 失败，拒绝写入，避免静默清空
    critical_missing = []
    for binding in source_bindings or []:
        if not isinstance(binding, dict):
            continue
        name = str(binding.get("name") or "")
        btype = str(binding.get("type") or "")
        if btype not in ("secret_text", "d1"):
            continue
        if name in ("DOMAINS", "DEFAULT_DOMAINS"):
            continue
        if not any(p.get("name") == name and p.get("type") == btype for p in preserved):
            critical_missing.append(f"{name}:{btype}")
    if critical_missing:
        return {
            "ok": False,
            "domains_json": payload,
            "error": (
                "拒绝写入：无法安全保留关键绑定 "
                + ", ".join(critical_missing)
                + "（避免清空 JWT_SECRET/D1）"
            ),
        }

    domains_type = _detect_domains_binding_type(source_bindings)
    had_default = any(
        isinstance(b, dict) and b.get("name") == "DEFAULT_DOMAINS"
        for b in (source_bindings or [])
    )
    # 若历史上有 DEFAULT_DOMAINS，或当前没有其它域名变量，则同步写入
    include_default = had_default or True
    domain_bindings = _build_domains_bindings(
        domains, domains_type=domains_type, include_default=include_default
    )
    bindings = preserved + domain_bindings
    settings_obj = {"bindings": bindings}
    patch = _cf_multipart_patch_settings(token, account_id, worker_name, settings_obj)
    if patch.get("success"):
        # 写后校验：关键绑定与域名必须仍在
        verify = read_worker_domains(token, account_id, worker_name)
        if not verify.get("ok"):
            return {
                "ok": False,
                "domains_json": payload,
                "error": f"写入后校验读取失败: {verify.get('error')}",
                "response": patch,
            }
        after_names = {
            str(b.get("name") or "")
            for b in (verify.get("bindings") or [])
            if isinstance(b, dict)
        }
        for item in preserved:
            name = str(item.get("name") or "")
            if name and name not in after_names:
                return {
                    "ok": False,
                    "domains_json": payload,
                    "error": (
                        f"写入后关键绑定丢失: {name} "
                        f"(type={item.get('type')})；已拒绝视为成功"
                    ),
                    "response": patch,
                }
        return {
            "ok": True,
            "domains_json": payload,
            "response": patch,
            "domains_binding_type": domains_type,
            "dropped_noncritical": dropped,
        }

    # 绝不回退到「只写 DOMAINS」——那会删掉 JWT_SECRET / DB
    return {
        "ok": False,
        "domains_json": payload,
        "error": (
            "multipart PATCH 失败（未使用危险 minimal 回退，以免清空 JWT_SECRET/D1）: "
            + _error_message(patch)
        ),
        "response": patch,
    }


def enable_email_routing_subdomain(
    token: str, zone_id: str, fqdn: str
) -> Dict[str, Any]:
    """
    在 Email Routing → Settings → Subdomains 中启用子域。
    对应 API: POST /zones/{zone_id}/email/routing/dns  body {"name": "<fqdn>"}
    需要 Zone Settings Write / DNS Edit 等权限。
    """
    import time

    fqdn = str(fqdn or "").strip().lower()
    if not fqdn or "." not in fqdn:
        return {"ok": False, "error": "empty or invalid FQDN"}
    last: Dict[str, Any] = {}
    # 仅使用完整 FQDN；纯 label 会被 CF 拒绝（must be a subdomains of ...）
    for attempt in range(1, 4):
        last = _cf_request(
            token, "POST", f"/zones/{zone_id}/email/routing/dns", body={"name": fqdn}
        )
        if last.get("success"):
            return {"ok": True, "response": last, "body": {"name": fqdn}}
        errors = last.get("errors") or []
        messages = " ".join(
            str(e.get("message") or e) for e in errors if isinstance(e, dict)
        ).lower()
        if any(
            key in messages
            for key in ("already", "exists", "enabled", "duplicate", "locked")
        ):
            return {
                "ok": True,
                "response": last,
                "body": {"name": fqdn},
                "already": True,
            }
        # 短暂重试：偶发 4xx/限流
        if attempt < 3:
            time.sleep(1.0 * attempt)
    return {
        "ok": False,
        "error": _error_message(last),
        "response": last,
        "hint": (
            "当前 API Token 可能缺少 Zone Settings Write / DNS Edit；"
            "Dashboard 里 Email Routing → Settings → Subdomains 不会自动出现新行。"
        ),
    }


def list_email_routing_subdomains(token: str, zone_id: str) -> Dict[str, Any]:
    """列出 Email Routing → Settings → Subdomains 中的全部 FQDN。"""
    res = _cf_request(token, "GET", f"/zones/{zone_id}/email/routing")
    if not res.get("success"):
        return {"ok": False, "domains": [], "error": _error_message(res), "response": res}
    result = res.get("result") or {}
    subs = result.get("subdomains") if isinstance(result, dict) else None
    if not isinstance(subs, list):
        subs = []
    domains: List[str] = []
    seen = set()
    for item in subs:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        if name and name not in seen:
            seen.add(name)
            domains.append(name)
    return {"ok": True, "domains": domains, "response": res}


def email_routing_has_subdomain(
    token: str, zone_id: str, fqdn: str
) -> Optional[bool]:
    """True=仍在列表, False=已不在, None=查询失败。"""
    fqdn = str(fqdn or "").strip().lower()
    listed = list_email_routing_subdomains(token, zone_id)
    if not listed.get("ok"):
        return None
    return fqdn in (listed.get("domains") or [])


def disable_email_routing_subdomain(
    token: str,
    zone_id: str,
    fqdn: str,
    *,
    retries: int = 3,
) -> Dict[str, Any]:
    """拆除 Email Routing 子域：DELETE 后必须 list 复查，禁止仅凭 not found 判成功。"""
    import time

    fqdn = str(fqdn or "").strip().lower()
    if not fqdn:
        return {"ok": True, "verified": True, "attempts": 0}
    retries = max(1, min(int(retries or 3), 5))
    last: Dict[str, Any] = {}
    for attempt in range(1, retries + 1):
        present = email_routing_has_subdomain(token, zone_id, fqdn)
        if present is False:
            return {
                "ok": True,
                "verified": True,
                "attempts": attempt,
                "already_absent": True,
                "via": "list_before_delete",
            }
        last = _cf_request(
            token, "DELETE", f"/zones/{zone_id}/email/routing/dns", body={"name": fqdn}
        )
        # 无论 DELETE 成功/not found，都必须复查列表
        present_after = email_routing_has_subdomain(token, zone_id, fqdn)
        if present_after is False:
            return {
                "ok": True,
                "verified": True,
                "attempts": attempt,
                "response": last,
                "via": "DELETE email/routing/dns + list verify",
                "delete_success": bool(last.get("success")),
            }
        if present_after is None:
            err = "Email Routing 列表复查失败，无法确认子域已拆除"
        elif last.get("success"):
            err = f"DELETE 返回成功但列表仍含 {fqdn}"
        else:
            err = _error_message(last) or f"拆除后列表仍含 {fqdn}"
        if attempt < retries:
            time.sleep(0.5 * attempt)
            continue
        return {
            "ok": False,
            "verified": False,
            "attempts": attempt,
            "error": err,
            "response": last,
            "still_present": present_after is True,
        }
    return {
        "ok": False,
        "verified": False,
        "attempts": retries,
        "error": _error_message(last) or "Email Routing 拆除失败",
        "response": last,
    }


def verify_new_address(
    worker_base: str,
    domain: str,
    path: str = "/api/new_address",
) -> Dict[str, Any]:
    """用 curl_cffi 模拟浏览器，避免 Worker 前的 CF 1010 拦截。"""
    base = (worker_base or "").rstrip("/")
    if not base:
        return {"ok": False, "error": "cloudflare_api_base 为空"}
    url = f"{base}{path if path.startswith('/') else '/' + path}"
    try:
        from curl_cffi import requests as cf_requests

        resp = cf_requests.post(
            url,
            json={"domain": domain},
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=30,
            impersonate="chrome",
        )
        try:
            data = resp.json() if resp.text else {}
        except Exception:
            data = {"_raw": (resp.text or "")[:300]}
        address = ""
        jwt = ""
        if isinstance(data, dict):
            address = str(data.get("address") or data.get("email") or "")
            jwt = str(data.get("jwt") or data.get("token") or "")
        ok = resp.status_code < 400 and bool(address and jwt)
        return {
            "ok": ok,
            "status": resp.status_code,
            "address": address,
            "error": "" if ok else f"status={resp.status_code} body={str(data)[:300]}",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def provision_one(cfg: Dict[str, Any], log: LogFn = None) -> ProvisionResult:
    """创建随机子域：Email Routing 子域 + Worker DOMAINS + new_address 验证。"""
    token = str(cfg.get("cf_api_token") or "").strip()
    if not token:
        return ProvisionResult(ok=False, error="cf_api_token 未配置")
    root = str(cfg.get("dynamic_subdomain_root") or FIXED_ROOT).strip().lower() or FIXED_ROOT
    if root != FIXED_ROOT:
        return ProvisionResult(ok=False, error=f"dynamic_subdomain_root 必须是 {FIXED_ROOT}")
    worker_name = str(cfg.get("cf_worker_name") or "temp-email").strip() or "temp-email"
    worker_base = str(cfg.get("cloudflare_api_base") or "").strip()
    accounts_path = str(cfg.get("cloudflare_path_accounts") or "/api/new_address").strip()
    if accounts_path and not accounts_path.startswith("/"):
        accounts_path = "/" + accounts_path
    keep = parse_keep_domains(str(cfg.get("dynamic_subdomain_keep") or ""), root)
    # 缺 Email Routing 权限时是否仍继续（默认 false：必须出现在 Subdomains 列表）
    allow_skip_routing = bool(cfg.get("dynamic_subdomain_allow_skip_email_routing", False))

    last_error = ""
    for attempt in range(1, 3):
        try:
            min_len = int(cfg.get("dynamic_subdomain_label_min_len") or 10)
            max_len = int(cfg.get("dynamic_subdomain_label_max_len") or 14)
            domain = generate_subdomain(
                root,
                exclude_labels={k.split(".")[0] for k in keep},
                min_len=min_len,
                max_len=max_len,
            )
            _log(log, f"[*] 动态子域尝试 {attempt}/2: {domain} (token{mask_token(token)})")
            zone_id = get_zone_id(token, root, str(cfg.get("cf_zone_id") or "").strip())
            account_id = get_account_id(
                token, zone_id, str(cfg.get("cf_account_id") or "").strip()
            )

            # 1) Email Routing Subdomains（你在 Dashboard 看到的那一页）
            routing = enable_email_routing_subdomain(token, zone_id, domain)
            if not routing.get("ok"):
                last_error = (
                    f"Email Routing 启用子域失败: {routing.get('error')}. "
                    f"{routing.get('hint') or ''}"
                )
                _log(log, f"[!] {last_error}")
                if not allow_skip_routing:
                    continue
                _log(log, "[!] 已配置允许跳过 Email Routing，继续写 Worker DOMAINS（收信可能失败）")
            else:
                _log(log, f"[+] Email Routing 子域已启用: {domain}")

            # 2) Worker 变量 DOMAINS（temp-email 允许用哪些后缀建邮箱）
            current = read_worker_domains(token, account_id, worker_name)
            existing = list(current.get("domains") or []) if current.get("ok") else []
            if not current.get("ok"):
                _log(log, f"[!] 读取 Worker DOMAINS 失败，将从 keep+新域重建: {current.get('error')}")
                existing = list(keep)
            merged = merge_domains(existing, add=keep + [domain])
            written = write_worker_domains(
                token,
                account_id,
                worker_name,
                merged,
                existing_bindings=current.get("bindings") if current.get("ok") else None,
            )
            if not written.get("ok"):
                last_error = f"写入 Worker DOMAINS 失败: {written.get('error')}"
                _log(log, f"[!] {last_error}")
                if routing.get("ok"):
                    disable_email_routing_subdomain(token, zone_id, domain)
                continue

            # 3) new_address 探测（Worker 环境变量偶发延迟，短暂重试）
            import time

            verify: Dict[str, Any] = {"ok": False}
            for verify_try in range(1, 4):
                if verify_try > 1:
                    time.sleep(1.5 * (verify_try - 1))
                # 以重新读取 DOMAINS 为准，确认已写入
                reread = read_worker_domains(token, account_id, worker_name)
                if reread.get("ok") and domain not in (reread.get("domains") or []):
                    _log(log, f"[!] Worker DOMAINS 尚未包含 {domain}，重写一次")
                    write_worker_domains(
                        token,
                        account_id,
                        worker_name,
                        merged,
                        existing_bindings=reread.get("bindings") or current.get("bindings"),
                    )
                    time.sleep(1.0)
                verify = verify_new_address(worker_base, domain, path=accounts_path)
                if verify.get("ok"):
                    break
                _log(
                    log,
                    f"[!] new_address 验证未通过 ({verify_try}/3): {verify.get('error')}",
                )
            if not verify.get("ok"):
                last_error = f"new_address 验证失败: {verify.get('error')}"
                _log(log, f"[!] {last_error}")
                rolled = merge_domains(merged, remove=[domain])
                write_worker_domains(
                    token,
                    account_id,
                    worker_name,
                    rolled,
                    existing_bindings=current.get("bindings") if current.get("ok") else None,
                )
                if routing.get("ok"):
                    disable_email_routing_subdomain(token, zone_id, domain)
                continue
            _log(log, f"[+] 动态子域就绪: {domain}")
            return ProvisionResult(
                ok=True,
                domain=domain,
                domains_json=str(written.get("domains_json") or domains_to_json(merged)),
            )
        except Exception as exc:
            last_error = str(exc)
            _log(log, f"[!] 动态子域创建异常: {exc}")
    return ProvisionResult(ok=False, error=last_error or "动态子域创建失败")


def teardown_one(domain: str, cfg: Dict[str, Any], log: LogFn = None) -> bool:
    """从 Worker DOMAINS + Email Routing 拆除子域；两侧都成功才返回 True。"""
    domain = str(domain or "").strip().lower()
    if not domain:
        return True
    token = str(cfg.get("cf_api_token") or "").strip()
    if not token:
        _log(log, f"[!] teardown 跳过（无 cf_api_token）: {domain}")
        return False
    root = str(cfg.get("dynamic_subdomain_root") or FIXED_ROOT).strip().lower() or FIXED_ROOT
    worker_name = str(cfg.get("cf_worker_name") or "temp-email").strip() or "temp-email"
    keep = parse_keep_domains(str(cfg.get("dynamic_subdomain_keep") or ""), root)
    retries = int(cfg.get("dynamic_subdomain_teardown_retries") or 3)
    if domain in keep:
        _log(log, f"[*] teardown 跳过 keep 域: {domain}")
        return True
    ok_all = True
    try:
        zone_id = get_zone_id(token, root, str(cfg.get("cf_zone_id") or "").strip())
        account_id = get_account_id(
            token, zone_id, str(cfg.get("cf_account_id") or "").strip()
        )
        current = read_worker_domains(token, account_id, worker_name)
        existing = list(current.get("domains") or []) if current.get("ok") else []
        if not current.get("ok"):
            _log(log, f"[!] teardown 读取 DOMAINS 失败: {current.get('error')}")
            ok_all = False
        else:
            remaining = merge_domains(existing, add=keep, remove=[domain])
            written = write_worker_domains(
                token,
                account_id,
                worker_name,
                remaining,
                existing_bindings=current.get("bindings"),
            )
            if not written.get("ok"):
                _log(log, f"[!] teardown Worker 写入失败 {domain}: {written.get('error')}")
                ok_all = False
            else:
                _log(log, f"[+] 已从 Worker DOMAINS 移除: {domain}")

        routing = disable_email_routing_subdomain(
            token, zone_id, domain, retries=retries
        )
        if routing.get("ok") and routing.get("verified", True):
            _log(log, f"[+] 已拆除 Email Routing 子域（已复查）: {domain}")
        else:
            _log(
                log,
                f"[!] Email Routing 拆除未通过复查: {domain}（Worker 可能已移除）: "
                f"{routing.get('error')}",
            )
            ok_all = False
        return ok_all
    except Exception as exc:
        _log(log, f"[!] teardown 异常 {domain}: {exc}")
        return False


def purge_email_routing_residuals(
    cfg: Dict[str, Any], log: LogFn = None
) -> Dict[str, Any]:
    """删除所有非 keep 的 Email Routing 子域，并将 Worker DOMAINS 收敛为 keep。"""
    token = str(cfg.get("cf_api_token") or "").strip()
    root = str(cfg.get("dynamic_subdomain_root") or FIXED_ROOT).strip().lower() or FIXED_ROOT
    worker_name = str(cfg.get("cf_worker_name") or "temp-email").strip() or "temp-email"
    keep = parse_keep_domains(str(cfg.get("dynamic_subdomain_keep") or ""), root)
    keep_set = set(keep)
    retries = int(cfg.get("dynamic_subdomain_teardown_retries") or 3)
    empty = {
        "ok": False,
        "kept": list(keep),
        "removed": [],
        "failed": [],
        "before": 0,
        "after": 0,
    }
    if not token:
        empty["error"] = "cf_api_token 未配置"
        _log(log, f"[!] 残留清扫跳过: {empty['error']}")
        return empty
    try:
        zone_id = get_zone_id(token, root, str(cfg.get("cf_zone_id") or "").strip())
        account_id = get_account_id(
            token, zone_id, str(cfg.get("cf_account_id") or "").strip()
        )
        listed = list_email_routing_subdomains(token, zone_id)
        if not listed.get("ok"):
            empty["error"] = listed.get("error") or "list Email Routing 失败"
            _log(log, f"[!] 残留清扫失败: {empty['error']}")
            return empty
        domains = list(listed.get("domains") or [])
        before = len(domains)
        to_remove = [d for d in domains if d not in keep_set]
        removed: List[str] = []
        failed: List[Dict[str, str]] = []
        for domain in to_remove:
            routing = disable_email_routing_subdomain(
                token, zone_id, domain, retries=retries
            )
            if routing.get("ok") and routing.get("verified", True):
                removed.append(domain)
            else:
                failed.append(
                    {"domain": domain, "error": str(routing.get("error") or "unknown")}
                )

        # Worker DOMAINS 收敛为 keep
        current = read_worker_domains(token, account_id, worker_name)
        worker_ok = True
        if current.get("ok"):
            written = write_worker_domains(
                token,
                account_id,
                worker_name,
                list(keep),
                existing_bindings=current.get("bindings"),
            )
            if not written.get("ok"):
                worker_ok = False
                _log(
                    log,
                    f"[!] 残留清扫：Worker DOMAINS 收敛失败: {written.get('error')}",
                )
            else:
                _log(log, f"[+] 残留清扫：Worker DOMAINS 已收敛为 keep ({', '.join(keep)})")
        else:
            worker_ok = False
            _log(log, f"[!] 残留清扫：读取 Worker DOMAINS 失败: {current.get('error')}")

        after_list = list_email_routing_subdomains(token, zone_id)
        after_domains = list(after_list.get("domains") or []) if after_list.get("ok") else []
        after = len(after_domains) if after_list.get("ok") else before
        ok = worker_ok and not failed and after_list.get("ok") is True
        _log(
            log,
            f"[*] 残留清扫: Routing {before}→{after}, 删除 {len(removed)}, 失败 {len(failed)}",
        )
        return {
            "ok": ok,
            "kept": [d for d in after_domains if d in keep_set] or list(keep),
            "removed": removed,
            "failed": failed,
            "before": before,
            "after": after,
        }
    except Exception as exc:
        empty["error"] = str(exc)
        _log(log, f"[!] 残留清扫异常: {exc}")
        return empty


def count_email_routing_subdomains(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """供 soft_limit 判断：返回当前 Email Routing 子域数量。"""
    token = str(cfg.get("cf_api_token") or "").strip()
    root = str(cfg.get("dynamic_subdomain_root") or FIXED_ROOT).strip().lower() or FIXED_ROOT
    if not token:
        return {"ok": False, "count": 0, "error": "cf_api_token 未配置"}
    try:
        zone_id = get_zone_id(token, root, str(cfg.get("cf_zone_id") or "").strip())
        listed = list_email_routing_subdomains(token, zone_id)
        if not listed.get("ok"):
            return {"ok": False, "count": 0, "error": listed.get("error")}
        domains = list(listed.get("domains") or [])
        return {"ok": True, "count": len(domains), "domains": domains}
    except Exception as exc:
        return {"ok": False, "count": 0, "error": str(exc)}
