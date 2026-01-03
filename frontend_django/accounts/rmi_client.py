import json
import os
import subprocess
import uuid
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

JAVA_BIN = os.environ.get("JAVA_BIN", "java")

JAVA_TIMEOUT_SEC = int(os.environ.get("JAVA_TIMEOUT_SEC", "5"))

JAVA_CLASSPATH = os.pathsep.join(
    [
        os.path.join(PROJECT_ROOT, "out", "production", "BankDistributedSystem"),
        os.path.join(PROJECT_ROOT, "backend_rmi", "lib", "mysql-connector-j-9.5.0.jar"),
    ]
)

JAVA_MAIN_CLASS = "ma.fsa.bank.client.RmiClient"

def _extract_json(text: str) -> Optional[str]:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    raw = text[start : end + 1]

    cleaned_chars = []
    for ch in raw:
        cleaned_chars.append(" " if ord(ch) < 32 else ch)
    return "".join(cleaned_chars).strip()


def _fallback_error(request_id: str, message: str, error_code: str, raw: str = "") -> Dict[str, Any]:

    return {
        "success": False,
        "ok": False,
        "message": message,
        "data": None,
        "error": {"details": raw[:800] if raw else ""},
        "error_code": error_code,
        "request_id": request_id,
    }


def _ensure_contract(obj: Dict[str, Any], fallback_request_id: str) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        obj = {}

    if not obj.get("request_id"):
        obj["request_id"] = fallback_request_id

    obj["success"] = bool(obj.get("success", False))
    obj["ok"] = bool(obj.get("success"))

    if obj.get("message") is None:
        obj["message"] = "OK" if obj["success"] else "Erreur"

    if "data" not in obj:
        obj["data"] = None
    if "error" not in obj:
        obj["error"] = None
    if "error_code" not in obj:
        obj["error_code"] = None

    return obj


def _flatten_for_legacy_usage(args_list: List[str], obj: Dict[str, Any]) -> Dict[str, Any]:
    cmd = args_list[0] if args_list else ""
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}

    if not isinstance(data, dict):
        return obj

    def copy_if_present(src_key: str, dest_key: str):
        if dest_key not in obj and src_key in data:
            obj[dest_key] = data.get(src_key)

    if cmd == "login":
        for k in ["id", "client_id", "username", "role", "active", "is_super_admin"]:
            copy_if_present(k, k)

    if cmd == "create_account":
        for k in ["id", "number", "balance"]:
            copy_if_present(k, k)

    if cmd == "get_client_accounts":
        copy_if_present("accounts", "accounts")

    if cmd == "get_transactions":
        copy_if_present("transactions", "transactions")
        copy_if_present("account", "account")

    if cmd == "get_all_transactions":
        copy_if_present("transactions", "transactions")

    if cmd == "list_users":
        copy_if_present("users", "users")

    if cmd == "list_branches":
        copy_if_present("branches", "branches")

    if cmd == "admin_stats":
        copy_if_present("stats", "stats")

    if cmd == "get_user_profile":
        copy_if_present("profile", "profile")

    if cmd == "get_balance":
        for k in ["account", "balance"]:
            copy_if_present(k, k)

    if cmd == "get_client_type":
        for k in ["client_id", "client_type"]:
            copy_if_present(k, k)

    if cmd == "set_client_type":
        for k in ["client_id", "client_type"]:
            copy_if_present(k, k)

    if cmd == "get_limits":
        for k in ["account", "client_type", "daily_transfer_limit", "daily_debit_limit"]:
            copy_if_present(k, k)

    return obj


def _resolve_request_id(request_id: Optional[str]) -> str:
    rid = (request_id or "").strip()
    return rid if rid else str(uuid.uuid4())

def call_rmi(args_list: List[str], request_id: Optional[str] = None) -> Dict[str, Any]:

    request_id = _resolve_request_id(request_id)

    cmd = [JAVA_BIN, "-cp", JAVA_CLASSPATH, JAVA_MAIN_CLASS] + args_list

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=JAVA_TIMEOUT_SEC,
        )

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        raw = stdout if stdout else stderr

        if not raw:
            return _fallback_error(
                request_id,
                f"Réponse vide du client Java (exit={proc.returncode})",
                "EMPTY_RESPONSE",
            )

        json_text = _extract_json(raw)
        if not json_text:
            msg = "Service bancaire indisponible, réessayez plus tard."
            code = "RMI_UNAVAILABLE" if proc.returncode != 0 else "INVALID_JSON"
            return _fallback_error(request_id, msg, code, raw=raw)

        try:
            obj = json.loads(json_text)
        except json.JSONDecodeError as e:
            return _fallback_error(
                request_id,
                "Service bancaire indisponible, réessayez plus tard.",
                "INVALID_JSON",
                raw=f"{str(e)} | {raw}",
            )

        obj = _ensure_contract(obj, request_id)

        obj["request_id"] = request_id
        obj["ok"] = bool(obj.get("success"))

        obj = _flatten_for_legacy_usage(args_list, obj)
        return obj

    except subprocess.TimeoutExpired:
        return _fallback_error(
            request_id,
            "Service bancaire indisponible, réessayez plus tard.",
            "TIMEOUT",
        )
    except FileNotFoundError:
        return _fallback_error(request_id, f"Java introuvable: {JAVA_BIN}", "JAVA_NOT_FOUND")
    except Exception as e:
        return _fallback_error(
            request_id,
            "Service bancaire indisponible, réessayez plus tard.",
            "CLIENT_ERROR",
            raw=str(e),
        )


def create_account(client_id: int, acc_type: str, currency: str, branch_id: int, request_id: Optional[str] = None):
    return call_rmi(["create_account", str(client_id), str(branch_id), acc_type, currency], request_id=request_id)

def close_account(account_number: str, request_id: Optional[str] = None):
    return call_rmi(["close_account", account_number], request_id=request_id)

def login(username: str, password: str, request_id: Optional[str] = None):
    return call_rmi(["login", username, password], request_id=request_id)

def register(
        username: str,
        password: str,
        branch_id: int,
        first_name: str,
        last_name: str,
        cin: str,
        email: str = "",
        phone: str = "",
        address: str = "",
        request_id: Optional[str] = None,
):
    def norm(v: str) -> str:
        v = (v or "").strip()
        return v if v else "-"

    return call_rmi(
        [
            "register",
            norm(username),
            norm(password),
            str(branch_id),
            norm(first_name),
            norm(last_name),
            norm(cin),
            norm(email),
            norm(phone),
            norm(address),
        ],
        request_id=request_id,
    )

def transfer(from_account: str, to_account: str, amount: float, request_id: Optional[str] = None):
    return call_rmi(["transfer", from_account, to_account, str(amount)], request_id=request_id)

def deposit(account_number: str, amount: float, request_id: Optional[str] = None):
    return call_rmi(["deposit", account_number, str(amount)], request_id=request_id)

def withdraw(account_number: str, amount: float, request_id: Optional[str] = None):
    return call_rmi(["withdraw", account_number, str(amount)], request_id=request_id)

def get_client_accounts(client_id: int, request_id: Optional[str] = None):
    return call_rmi(["get_client_accounts", str(client_id)], request_id=request_id)

def get_balance(account_number: str, request_id: Optional[str] = None):
    return call_rmi(["get_balance", account_number], request_id=request_id)

def get_transactions(account_number: str, request_id: Optional[str] = None):
    return call_rmi(["get_transactions", account_number], request_id=request_id)

def list_users(request_id: Optional[str] = None):
    return call_rmi(["list_users"], request_id=request_id)

def create_admin(username: str, password: str, request_id: Optional[str] = None):
    return call_rmi(["create_admin", username, password], request_id=request_id)

def set_user_active(user_id: int, active: bool, request_id: Optional[str] = None):
    return call_rmi(["set_user_active", str(user_id), "true" if active else "false"], request_id=request_id)

def get_admin_stats(request_id: Optional[str] = None):
    return call_rmi(["admin_stats"], request_id=request_id)

def get_all_transactions(request_id: Optional[str] = None):
    return call_rmi(["get_all_transactions"], request_id=request_id)

def get_branches(request_id: Optional[str] = None):
    return call_rmi(["list_branches"], request_id=request_id)

def get_client_type(client_id: int, request_id: Optional[str] = None):
    return call_rmi(["get_client_type", str(client_id)], request_id=request_id)

def set_client_type(client_id: int, client_type: str, request_id: Optional[str] = None):
    return call_rmi(["set_client_type", str(client_id), client_type], request_id=request_id)

def get_limits(account_number: str, request_id: Optional[str] = None):
    return call_rmi(["get_limits", account_number], request_id=request_id)

def get_user_profile(user_id: int, request_id: Optional[str] = None):
    return call_rmi(["get_user_profile", str(user_id)], request_id=request_id)

def update_user_profile(
        user_id: int,
        username: str,
        first_name: str,
        last_name: str,
        email: str,
        phone: str,
        address: str,
        request_id: Optional[str] = None,
):
    def norm(v: str) -> str:
        v = (v or "").strip()
        return v if v else "-"

    return call_rmi(
        [
            "update_user_profile",
            str(user_id),
            norm(username),
            norm(first_name),
            norm(last_name),
            norm(email),
            norm(phone),
            norm(address),
        ],
        request_id=request_id,
    )

def admin_reset_password(actor_user_id: int, target_user_id: int, new_password: str, request_id: Optional[str] = None):
    return call_rmi(["admin_reset_password", str(actor_user_id), str(target_user_id), new_password], request_id=request_id)
def delete_user(actor_user_id: int, target_user_id: int):
    return call_rmi(["delete_user", str(actor_user_id), str(target_user_id)])
