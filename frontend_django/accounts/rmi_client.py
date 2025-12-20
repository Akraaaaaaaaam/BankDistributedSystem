import json
import os


import subprocess
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

JAVA_BIN = os.environ.get("JAVA_BIN", "java")
JAVA_TIMEOUT_SEC = int(os.environ.get("JAVA_TIMEOUT_SEC", "20"))


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


def call_rmi(args_list: List[str]) -> Dict[str, Any]:

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

        if proc.returncode != 0 and not raw:
            return {"success": False, "error": f"Java exit code={proc.returncode}"}

        json_text = _extract_json(raw)
        if not json_text:
            return {"success": False, "error": f"Réponse Java non valide (brut: {raw})"}

        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Réponse Java non valide (JSON): {e}", "raw": raw}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout lors de l'appel Java/RMI"}
    except FileNotFoundError:
        return {"success": False, "error": f"Java introuvable: {JAVA_BIN}. Vérifie JAVA_BIN/JAVA_HOME."}
    except Exception as e:
        return {"success": False, "error": str(e)}




def create_account(client_id: int, acc_type: str, currency: str, branch_id: int):
    return call_rmi(["create_account", str(client_id), str(branch_id), acc_type, currency])


def close_account(account_number: str):
    return call_rmi(["close_account", account_number])


def login(username: str, password: str):
    return call_rmi(["login", username, password])


def register(username: str, password: str, branch_id: int,
             first_name: str, last_name: str, cin: str,
             email: str = "", phone: str = "", address: str = ""):

    def norm(v: str) -> str:
        v = (v or "").strip()
        return v if v else "-"


    return call_rmi([
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
    ])



def transfer(from_account: str, to_account: str, amount: float):
    return call_rmi(["transfer", from_account, to_account, str(amount)])


def deposit(account_number: str, amount: float):
    return call_rmi(["deposit", account_number, str(amount)])


def withdraw(account_number: str, amount: float):
    return call_rmi(["withdraw", account_number, str(amount)])


def get_client_accounts(client_id: int):
    return call_rmi(["get_client_accounts", str(client_id)])


def get_balance(account_number: str):
    return call_rmi(["get_balance", account_number])


def get_transactions(account_number: str):
    return call_rmi(["get_transactions", account_number])


def list_users():
    return call_rmi(["list_users"])


def create_admin(username: str, password: str):
    return call_rmi(["create_admin", username, password])


def set_user_active(user_id: int, active: bool):
    return call_rmi(["set_user_active", str(user_id), "true" if active else "false"])


def get_admin_stats():
    return call_rmi(["admin_stats"])


def get_all_transactions():
    return call_rmi(["get_all_transactions"])


def get_branches():
    return call_rmi(["list_branches"])


def get_client_type(client_id: int):
    return call_rmi(["get_client_type", str(client_id)])


def set_client_type(client_id: int, client_type: str):
    return call_rmi(["set_client_type", str(client_id), client_type])


def get_limits(account_number: str):
    return call_rmi(["get_limits", account_number])
def get_user_profile(user_id: int):
    return call_rmi(["get_user_profile", str(user_id)])


def update_user_profile(user_id: int, username: str, first_name: str, last_name: str, email: str, phone: str, address: str):

    def norm(v: str) -> str:
        v = (v or "").strip()
        return v if v else "-"

    return call_rmi([
        "update_user_profile",
        str(user_id),
        norm(username),
        norm(first_name),
        norm(last_name),
        norm(email),
        norm(phone),
        norm(address),
    ])
def admin_reset_password(actor_user_id: int, target_user_id: int, new_password: str):
    return call_rmi(["admin_reset_password", str(actor_user_id), str(target_user_id), new_password])
