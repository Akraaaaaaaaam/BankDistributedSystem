from __future__ import annotations

from datetime import datetime
from functools import wraps
import csv
import secrets
from typing import Any, Dict, List, Set, Optional
import logging

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.utils.dateparse import parse_date
from django.utils.http import url_has_allowed_host_and_scheme

from .forms import RegisterForm
from .models import AuditLog
from . import rmi_client

from .rmi_client import (
    login as rmi_login,
    transfer as rmi_transfer,
    get_client_accounts,
    deposit as rmi_deposit,
    withdraw as rmi_withdraw,
    get_transactions as rmi_get_transactions,
    create_account as rmi_create_account,
    close_account as rmi_close_account,
    list_users as rmi_list_users,
    create_admin as rmi_create_admin,
    set_user_active as rmi_set_user_active,
    get_all_transactions as rmi_get_all_transactions,
    get_branches as rmi_get_branches,
    get_user_profile as rmi_get_user_profile,
    update_user_profile as rmi_update_user_profile,
)

logger = logging.getLogger("bank")


RMI_DOWN_MSG = "Service bancaire indisponible, réessayez plus tard."


def get_request_id(request) -> str:
    rid = getattr(request, "request_id", None)
    if rid:
        return str(rid)

    rid2 = None
    try:
        rid2 = request.session.get("request_id")
    except Exception:
        pass

    return str(rid2 or "-")


def log_info(request, message: str, **ctx) -> None:
    try:
        logger.info(f"{message} ctx={ctx}", extra={"request_id": get_request_id(request)})
    except Exception:
        pass


def get_client_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def log_event(request, action: str) -> None:

    try:
        user = request.session.get("user")
        uid = user.get("id") if isinstance(user, dict) else None
        AuditLog.objects.create(
            user_id=uid,
            action=(action or "")[:100],
            ip_address=get_client_ip(request) or None,
        )
    except Exception:
        pass


def _safe_next_redirect(request, default_name: str):
    next_url = (request.POST.get("next") or request.GET.get("next") or "").strip()
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return redirect(next_url)
    return redirect(default_name)


def _otp_ok(request) -> bool:
    return (not request.session.get("otp_required")) or bool(request.session.get("otp_verified"))


def _fmt_req(resp: Dict[str, Any]) -> str:
    rid = resp.get("request_id") if isinstance(resp, dict) else None
    return f" (req: {rid})" if rid else ""


def _is_rmi_down(resp: Dict[str, Any]) -> bool:
    if not isinstance(resp, dict):
        return True
    code = (resp.get("error_code") or "").upper()
    return code in {"TIMEOUT", "RMI_UNAVAILABLE", "JAVA_NOT_FOUND", "CLIENT_ERROR", "EMPTY_RESPONSE", "INVALID_JSON"}


def _resp_message(resp: Dict[str, Any], default: str) -> str:

    if not isinstance(resp, dict):
        return str(default)

    if _is_rmi_down(resp):
        return RMI_DOWN_MSG + _fmt_req(resp)

    msg = resp.get("message")
    if not msg:
        err = resp.get("error")
        if isinstance(err, dict) and err.get("details"):
            msg = err.get("details")
        else:
            msg = err

    if not msg:
        msg = default

    return str(msg) + _fmt_req(resp)


def log_rmi(request, action: str, resp: Dict[str, Any], **ctx) -> None:

    try:
        http_rid = get_request_id(request)
        msg = f"RMI {action} success={resp.get('success')} code={resp.get('error_code')} ctx={ctx}"
        logger.info(msg, extra={"request_id": http_rid})
    except Exception:
        pass

def login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get("user")
        if not user:
            messages.error(request, "Veuillez vous connecter.")
            return redirect("login")

        if not _otp_ok(request):
            return redirect("otp_verify")

        return view_func(request, *args, **kwargs)

    return wrapper


def staff_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get("user")
        if not user:
            messages.error(request, "Veuillez vous connecter.")
            return redirect("login")

        if user.get("role") not in {"ADMIN", "EMPLOYEE"}:
            messages.error(request, "Accès réservé au personnel.")
            return redirect("dashboard")

        if not _otp_ok(request):
            return redirect("otp_verify")

        return view_func(request, *args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get("user")
        if not user:
            messages.error(request, "Veuillez vous connecter.")
            return redirect("login")

        if user.get("role") != "ADMIN":
            messages.error(request, "Accès réservé aux administrateurs.")
            return redirect("dashboard")

        if not _otp_ok(request):
            return redirect("otp_verify")

        return view_func(request, *args, **kwargs)

    return wrapper


def super_admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user = request.session.get("user")
        if not user:
            messages.error(request, "Veuillez vous connecter.")
            return redirect("login")

        if user.get("role") != "ADMIN":
            messages.error(request, "Accès réservé aux administrateurs.")
            return redirect("dashboard")

        if not user.get("is_super_admin"):
            messages.error(request, "Accès refusé (super-admin requis).")
            return redirect("admin_users_list")

        if not _otp_ok(request):
            return redirect("otp_verify")

        return view_func(request, *args, **kwargs)

    return wrapper


def _generate_otp_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _start_otp_flow(request, user_dict: dict) -> None:
    role = user_dict.get("role")
    otp_required = True

    request.session["otp_required"] = otp_required
    request.session["otp_verified"] = False

    if otp_required:
        code = _generate_otp_code()
        request.session["otp_code"] = code
        request.session["otp_created_at_ms"] = int(datetime.utcnow().timestamp() * 1000)
        print(f"[OTP] Code OTP pour {user_dict.get('username')} ({role}) = {code}", flush=True)


def _ensure_account_owned(request, account_number: str) -> bool:

    user = request.session.get("user") or {}
    client_id = user.get("client_id")
    if client_id is None:
        return False

    rid = get_request_id(request)
    acc_data = get_client_accounts(int(client_id), request_id=rid)
    log_rmi(request, "get_client_accounts(ownership_check)", acc_data, client_id=client_id)

    if not acc_data.get("success"):
        messages.error(request, _resp_message(acc_data, RMI_DOWN_MSG))
        return False

    owned: Set[str] = set()
    for a in acc_data.get("accounts", []) or []:
        if not isinstance(a, dict):
            continue
        num = a.get("number") or a.get("account_number")
        if num:
            owned.add(str(num))

    return str(account_number) in owned

def register_view(request):
    rid = get_request_id(request)

    br = rmi_get_branches(request_id=rid)
    log_rmi(request, "get_branches(register_form)", br)

    branches = br.get("branches", []) if br.get("success") else []
    if not br.get("success"):
        messages.error(request, _resp_message(br, "Impossible de charger la liste des agences."))

    if request.method == "POST":
        form = RegisterForm(request.POST, branches=branches)
        if form.is_valid():
            cd = form.cleaned_data

            resp = rmi_client.register(
                username=cd["username"],
                password=cd["password1"],
                branch_id=int(cd["branch_id"]),
                first_name=cd["first_name"],
                last_name=cd["last_name"],
                cin=cd["cin"],
                email=cd.get("email") or "",
                phone=cd.get("phone") or "",
                address=cd.get("address") or "",
                request_id=rid,
            )
            log_rmi(request, "register", resp, username=cd["username"], branch_id=cd["branch_id"])

            if resp.get("success"):
                messages.success(request, _resp_message(resp, "Inscription réussie ! Vous pouvez maintenant vous connecter."))
                log_event(request, "REGISTER_OK")
                return redirect("login")

            messages.error(request, _resp_message(resp, "Erreur lors de l'inscription."))
            log_event(request, "REGISTER_FAIL")
    else:
        form = RegisterForm(branches=branches)

    return render(request, "accounts/register.html", {"form": form, "branches": branches})


def login_view(request):
    if request.session.get("user") and _otp_ok(request):
        user = request.session["user"]
        role = user.get("role")
        if role in {"ADMIN", "EMPLOYEE"}:
            return redirect("admin_stats")
        return redirect("dashboard")

    if request.method == "POST":
        rid = get_request_id(request)
        username = (request.POST.get("username") or "").strip()
        password = request.POST.get("password") or ""

        resp = rmi_login(username, password, request_id=rid)
        log_rmi(request, "login", resp, username=username)

        if resp.get("success"):
            user_dict = {
                "id": resp.get("id"),
                "client_id": resp.get("client_id"),
                "username": resp.get("username"),
                "role": resp.get("role"),
                "is_super_admin": bool(resp.get("is_super_admin", False)),
            }

            request.session["user"] = user_dict
            log_event(request, "LOGIN_OK")
            log_info(request, "LOGIN_OK", user_id=user_dict.get("id"), role=user_dict.get("role"))

            _start_otp_flow(request, user_dict)

            if request.session.get("otp_required"):
                messages.info(request, "Un code OTP a été généré (voir console serveur).")
                return redirect("otp_verify")

            role = user_dict.get("role")
            if role in {"ADMIN", "EMPLOYEE"}:
                return redirect("admin_stats")
            return redirect("dashboard")

        messages.error(request, _resp_message(resp, "Identifiants invalides"))
        log_event(request, "LOGIN_FAILED")
        log_info(request, "LOGIN_FAILED", username=username)

    return render(request, "accounts/login.html")


def otp_verify_view(request):
    user = request.session.get("user")
    if not user:
        messages.error(request, "Veuillez vous connecter.")
        return redirect("login")

    if not request.session.get("otp_required"):
        request.session["otp_verified"] = True
        role = user.get("role")
        if role in {"ADMIN", "EMPLOYEE"}:
            return redirect("admin_stats")
        return redirect("dashboard")

    if request.method == "POST":
        code = (request.POST.get("code") or "").strip()
        expected = request.session.get("otp_code")

        if expected and code == expected:
            request.session["otp_verified"] = True
            request.session.pop("otp_code", None)

            log_event(request, "OTP_OK")
            log_info(request, "OTP_OK", user_id=(user or {}).get("id"))
            messages.success(request, "OTP validé")

            role = user.get("role")
            if role in {"ADMIN", "EMPLOYEE"}:
                return redirect("admin_stats")
            return redirect("dashboard")

        log_event(request, "OTP_BAD")
        log_info(request, "OTP_BAD", user_id=(user or {}).get("id"))
        messages.error(request, "Code OTP invalide.")

    return render(request, "accounts/otp_verify.html", {"user": user})


def logout_view(request):
    try:
        log_event(request, "LOGOUT")
        log_info(request, "LOGOUT", user_id=(request.session.get("user") or {}).get("id"))
    except Exception:
        pass
    request.session.flush()
    return redirect("login")

@login_required
def dashboard(request):
    user = request.session.get("user") or {}
    role = user.get("role")

    if role in {"ADMIN", "EMPLOYEE"}:
        return redirect("admin_stats")

    accounts: List[Dict[str, Any]] = []
    if user.get("client_id") is not None:
        rid = get_request_id(request)
        data = get_client_accounts(int(user["client_id"]), request_id=rid)
        log_rmi(request, "get_client_accounts(dashboard)", data, client_id=user.get("client_id"))

        if data.get("success"):
            accounts = data.get("accounts", [])
        else:
            messages.error(request, _resp_message(data, "Erreur lors du chargement des comptes."))

    return render(request, "accounts/dashboard.html", {"user": user, "accounts": accounts})


@login_required
def deposit_view(request):
    user = request.session.get("user") or {}
    rid = get_request_id(request)

    accounts = []
    if user.get("client_id") is not None:
        data = get_client_accounts(int(user["client_id"]), request_id=rid)
        log_rmi(request, "get_client_accounts(deposit_form)", data, client_id=user.get("client_id"))

        if data.get("success"):
            accounts = data.get("accounts", [])
        else:
            messages.error(request, _resp_message(data, "Erreur lors du chargement des comptes."))

    if request.method == "POST":
        account_number = request.POST.get("account_number")
        amount_str = request.POST.get("amount")

        if not account_number or not amount_str:
            messages.error(request, "Veuillez remplir tous les champs.")
            return redirect("deposit")

        if not _ensure_account_owned(request, account_number):
            return redirect("dashboard")

        try:
            amount = float(amount_str)
        except ValueError:
            messages.error(request, "Montant invalide.")
            return redirect("deposit")

        if amount <= 0:
            messages.error(request, "Le montant doit être positif.")
            return redirect("deposit")

        resp = rmi_deposit(account_number, amount, request_id=rid)
        log_rmi(request, "deposit", resp, account=account_number, amount=amount, user_id=user.get("id"))

        if resp.get("success"):
            messages.success(request, _resp_message(resp, "Dépôt effectué avec succès."))
            return redirect("dashboard")

        messages.error(request, _resp_message(resp, "Erreur lors du dépôt."))

    return render(request, "accounts/deposit.html", {"user": user, "accounts": accounts})


@login_required
def withdraw_view(request):
    user = request.session.get("user") or {}
    rid = get_request_id(request)

    accounts = []
    if user.get("client_id") is not None:
        data = get_client_accounts(int(user["client_id"]), request_id=rid)
        log_rmi(request, "get_client_accounts(withdraw_form)", data, client_id=user.get("client_id"))

        if data.get("success"):
            accounts = data.get("accounts", [])
        else:
            messages.error(request, _resp_message(data, "Erreur lors du chargement des comptes."))

    if request.method == "POST":
        account_number = request.POST.get("account_number")
        amount_str = request.POST.get("amount")

        if not account_number or not amount_str:
            messages.error(request, "Veuillez remplir tous les champs.")
            return redirect("withdraw")

        if not _ensure_account_owned(request, account_number):
            return redirect("dashboard")

        try:
            amount = float(amount_str)
        except ValueError:
            messages.error(request, "Montant invalide.")
            return redirect("withdraw")

        if amount <= 0:
            messages.error(request, "Le montant doit être positif.")
            return redirect("withdraw")

        resp = rmi_withdraw(account_number, amount, request_id=rid)
        log_rmi(request, "withdraw", resp, account=account_number, amount=amount, user_id=user.get("id"))

        if resp.get("success"):
            messages.success(request, _resp_message(resp, "Retrait effectué avec succès."))
            return redirect("dashboard")

        messages.error(request, _resp_message(resp, "Retrait refusé (solde insuffisant ou limite journalière dépassée)."))

    return render(request, "accounts/withdraw.html", {"user": user, "accounts": accounts})


@login_required
def transfer_view(request):
    user = request.session.get("user") or {}
    rid = get_request_id(request)

    accounts = []
    if user.get("client_id") is not None:
        resp_acc = get_client_accounts(int(user["client_id"]), request_id=rid)
        log_rmi(request, "get_client_accounts(transfer_form)", resp_acc, client_id=user.get("client_id"))

        if resp_acc.get("success"):
            accounts = resp_acc.get("accounts", [])
        else:
            messages.error(request, _resp_message(resp_acc, "Erreur lors du chargement des comptes."))

    if request.method == "POST":
        from_account = request.POST.get("from_account")
        to_account = request.POST.get("to_account")
        amount_str = request.POST.get("amount")

        if not from_account or not to_account or not amount_str:
            messages.error(request, "Veuillez remplir tous les champs.")
            return redirect("transfer")

        if not _ensure_account_owned(request, from_account):
            return redirect("dashboard")

        try:
            amount = float(amount_str)
        except ValueError:
            messages.error(request, "Montant invalide.")
            return redirect("transfer")

        if amount <= 0:
            messages.error(request, "Le montant doit être positif.")
            return redirect("transfer")

        resp = rmi_transfer(from_account, to_account, amount, request_id=rid)
        log_rmi(request, "transfer", resp, from_acc=from_account, to_acc=to_account, amount=amount, user_id=user.get("id"))

        if resp.get("success"):
            messages.success(request, _resp_message(resp, "Virement effectué avec succès."))
            return redirect("dashboard")

        messages.error(request, _resp_message(resp, "Erreur lors du virement."))

    return render(request, "accounts/transfer.html", {"user": user, "accounts": accounts})


@login_required
def transactions_view(request, account_number: str):
    user = request.session.get("user") or {}
    rid = get_request_id(request)

    if not _ensure_account_owned(request, account_number):
        return redirect("dashboard")

    data = rmi_get_transactions(account_number, request_id=rid)
    log_rmi(request, "get_transactions", data, account=account_number, user_id=user.get("id"))

    transactions = data.get("transactions", []) if data.get("success") else []

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur lors de la récupération des transactions."))

    for t in transactions:
        ts = t.get("date")
        if ts:
            try:
                dt = datetime.fromtimestamp(ts / 1000.0)
                t["date_obj"] = dt
                t["date_only"] = dt.date()
                t["date_str"] = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                t["date_obj"] = None
                t["date_only"] = None
                t["date_str"] = "-"
        else:
            t["date_obj"] = None
            t["date_only"] = None
            t["date_str"] = "-"

    date_from_str = request.GET.get("date_from") or ""
    date_to_str = request.GET.get("date_to") or ""
    tx_type = (request.GET.get("type") or "ALL").upper()
    order = request.GET.get("order") or "date_desc"
    amount_min_str = request.GET.get("amount_min") or ""
    amount_max_str = request.GET.get("amount_max") or ""

    date_from = parse_date(date_from_str) if date_from_str else None
    date_to = parse_date(date_to_str) if date_to_str else None

    try:
        amount_min = float(amount_min_str) if amount_min_str else None
    except ValueError:
        amount_min = None

    try:
        amount_max = float(amount_max_str) if amount_max_str else None
    except ValueError:
        amount_max = None

    filtered = []
    for t in transactions:
        ok = True
        d = t.get("date_only")

        if date_from and d and d < date_from:
            ok = False
        if date_to and d and d > date_to:
            ok = False
        if tx_type != "ALL" and (t.get("type") or "").upper() != tx_type:
            ok = False

        amt = t.get("amount")
        try:
            amt_val = float(amt) if amt is not None else None
        except Exception:
            amt_val = None

        if amount_min is not None and amt_val is not None and amt_val < amount_min:
            ok = False
        if amount_max is not None and amt_val is not None and amt_val > amount_max:
            ok = False

        if ok:
            filtered.append(t)

    if order == "date_asc":
        filtered.sort(key=lambda x: x.get("date_obj") or datetime.min)
    elif order == "amount_asc":
        filtered.sort(key=lambda x: float(x.get("amount") or 0.0))
    elif order == "amount_desc":
        filtered.sort(key=lambda x: float(x.get("amount") or 0.0), reverse=True)
    else:
        filtered.sort(key=lambda x: x.get("date_obj") or datetime.min, reverse=True)

    stats = {
        "total_count": len(filtered),
        "total_amount": 0.0,
        "by_type": {
            "DEPOSIT": {"count": 0, "sum": 0.0, "avg": 0.0},
            "WITHDRAWAL": {"count": 0, "sum": 0.0, "avg": 0.0},
            "TRANSFER": {"count": 0, "sum": 0.0, "avg": 0.0},
        },
        "first_balance": None,
        "last_balance": None,
    }

    if filtered:
        for t in filtered:
            amt = float(t.get("amount") or 0.0)
            stats["total_amount"] += amt
            typ = (t.get("type") or "").upper()
            if typ in stats["by_type"]:
                stats["by_type"][typ]["count"] += 1
                stats["by_type"][typ]["sum"] += amt

        for typ, obj in stats["by_type"].items():
            obj["avg"] = (obj["sum"] / obj["count"]) if obj["count"] > 0 else 0.0

        sorted_by_date = sorted(filtered, key=lambda x: x.get("date_obj") or datetime.min)
        stats["first_balance"] = sorted_by_date[0].get("balance_after")
        stats["last_balance"] = sorted_by_date[-1].get("balance_after")

    chart_labels = ["DEPOSIT", "WITHDRAWAL", "TRANSFER"]
    chart_values = [
        stats["by_type"]["DEPOSIT"]["sum"],
        stats["by_type"]["WITHDRAWAL"]["sum"],
        stats["by_type"]["TRANSFER"]["sum"],
    ]
    balance_labels = [t["date_str"] for t in filtered]
    balance_values = [t.get("balance_after") for t in filtered]

    return render(
        request,
        "accounts/transactions.html",
        {
            "user": user,
            "account_number": account_number,
            "transactions": filtered,
            "filters": {
                "date_from": date_from_str,
                "date_to": date_to_str,
                "type": tx_type,
                "order": order,
                "amount_min": amount_min_str,
                "amount_max": amount_max_str,
            },
            "stats": stats,
            "chart_labels": chart_labels,
            "chart_values": chart_values,
            "balance_labels": balance_labels,
            "balance_values": balance_values,
        },
    )


@login_required
def create_account_view(request):
    user = request.session.get("user") or {}
    client_id = user.get("client_id")
    rid = get_request_id(request)

    if client_id is None:
        messages.error(request, "Votre profil n'est pas associé à un client bancaire.")
        return redirect("dashboard")

    client_id = int(client_id)

    data_acc = get_client_accounts(client_id, request_id=rid)
    log_rmi(request, "get_client_accounts(create_account)", data_acc, client_id=client_id)

    accounts = data_acc.get("accounts", []) if data_acc.get("success") else []

    if not data_acc.get("success"):
        messages.error(request, _resp_message(data_acc, "Erreur lors du chargement des comptes."))

    branches = []
    data_br = rmi_get_branches(request_id=rid)
    log_rmi(request, "get_branches(create_account)", data_br)

    if data_br.get("success"):
        branches = data_br.get("branches", [])
    else:
        messages.error(request, _resp_message(data_br, "Erreur lors du chargement des agences."))

    if request.method == "POST":
        acc_type = (request.POST.get("type") or "CHECKING").strip().upper()
        currency = (request.POST.get("currency") or "MAD").strip().upper()
        branch_id_str = (request.POST.get("branch_id") or "").strip()

        if len(accounts) >= 3:
            messages.error(request, "Vous avez déjà le nombre maximum de comptes autorisés.")
            return redirect("create_account")

        if not branch_id_str:
            messages.error(request, "Veuillez sélectionner une agence.")
            return redirect("create_account")

        try:
            branch_id = int(branch_id_str)
        except ValueError:
            messages.error(request, "Agence invalide.")
            return redirect("create_account")

        resp = rmi_create_account(client_id, acc_type, currency, branch_id, request_id=rid)
        log_rmi(request, "create_account", resp, client_id=client_id, type=acc_type, currency=currency, branch_id=branch_id)

        if resp.get("success"):
            messages.success(request, _resp_message(resp, f"Compte créé avec succès : {resp.get('number')}"))
            return redirect("dashboard")

        messages.error(request, _resp_message(resp, "Erreur lors de la création du compte."))

    return render(request, "accounts/create_account.html", {"user": user, "accounts": accounts, "branches": branches})


@login_required
def export_transactions_csv(request, account_number: str):
    rid = get_request_id(request)

    if not _ensure_account_owned(request, account_number):
        return redirect("dashboard")

    data = rmi_get_transactions(account_number, request_id=rid)
    log_rmi(request, "get_transactions(export_csv)", data, account=account_number)

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur récupération transactions."))
        return redirect("transactions", account_number=account_number)

    txs = data.get("transactions", [])

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="transactions_{account_number}.csv"'

    writer = csv.writer(response)
    writer.writerow(["id", "type", "amount", "balance_after", "date_ms"])

    for t in txs:
        writer.writerow([t.get("id"), t.get("type"), t.get("amount"), t.get("balance_after"), t.get("date")])

    return response

@admin_required
def admin_users_list(request):
    rid = get_request_id(request)

    resp = rmi_list_users(request_id=rid)
    log_rmi(request, "list_users", resp)

    users = resp.get("users", []) if resp.get("success") else []

    if not resp.get("success"):
        messages.error(request, _resp_message(resp, "Erreur lors du chargement des utilisateurs."))

    q = (request.GET.get("q", "").strip().lower())
    role_filter = (request.GET.get("role", "ALL") or "ALL").upper()
    active_filter = (request.GET.get("active", "ALL") or "ALL").lower()

    filtered_users = []
    for u in users:
        username = str(u.get("username", "")).lower()
        role = (u.get("role") or "").upper()
        active = bool(u.get("active", False))

        if q and q not in username:
            continue
        if role_filter != "ALL" and role != role_filter:
            continue
        if active_filter == "true" and not active:
            continue
        if active_filter == "false" and active:
            continue

        filtered_users.append(u)

    total_users = len(users)
    total_admins = sum(1 for u in users if (u.get("role") or "").upper() == "ADMIN")
    total_clients = sum(1 for u in users if (u.get("role") or "").upper() == "CLIENT")
    total_employees = sum(1 for u in users if (u.get("role") or "").upper() == "EMPLOYEE")
    active_count = sum(1 for u in users if u.get("active"))
    inactive_count = total_users - active_count

    return render(
        request,
        "accounts/admin_users_list.html",
        {
            "user": request.session.get("user"),
            "users": filtered_users,
            "total_users": total_users,
            "total_admins": total_admins,
            "total_clients": total_clients,
            "total_employees": total_employees,
            "active_count": active_count,
            "inactive_count": inactive_count,
            "q": q,
            "role_filter": role_filter,
            "active_filter": active_filter,
        },
    )


@super_admin_required
def admin_create_admin(request):
    rid = get_request_id(request)

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        password1 = request.POST.get("password1") or ""
        password2 = request.POST.get("password2") or ""

        if not username or not password1 or not password2:
            messages.error(request, "Veuillez remplir tous les champs.")
            return redirect("admin_create_admin")

        if password1 != password2:
            messages.error(request, "Les mots de passe ne correspondent pas.")
            return redirect("admin_create_admin")

        if len(password1) < 4:
            messages.error(request, "Le mot de passe doit contenir au moins 4 caractères.")
            return redirect("admin_create_admin")

        resp = rmi_create_admin(username, password1, request_id=rid)
        log_rmi(request, "create_admin", resp, username=username)

        if resp.get("success"):
            messages.success(request, _resp_message(resp, "Administrateur créé avec succès."))
            log_event(request, "ADMIN_CREATE_ADMIN")
            return redirect("admin_users_list")

        messages.error(request, _resp_message(resp, "Erreur lors de la création de l'admin."))
        return redirect("admin_create_admin")

    return render(request, "accounts/admin_create_admin.html", {"user": request.session.get("user")})


@admin_required
def admin_set_user_active(request, user_id: int):
    rid = get_request_id(request)

    if request.method != "POST":
        messages.error(request, "Méthode non autorisée (POST requis).")
        return redirect("admin_users_list")

    action = (request.POST.get("action") or "").strip().lower()

    if action == "activate":
        new_active = True
    elif action == "deactivate":
        new_active = False
    else:
        messages.error(request, "Action invalide.")
        return redirect("admin_users_list")

    current_user = request.session.get("user") or {}
    if current_user.get("id") == user_id and not new_active:
        messages.error(request, "Vous ne pouvez pas désactiver votre propre compte.")
        return redirect("admin_users_list")

    resp = rmi_set_user_active(user_id, new_active, request_id=rid)
    log_rmi(request, "set_user_active", resp, target_user_id=user_id, new_active=new_active, actor_id=current_user.get("id"))

    if resp.get("success"):
        messages.success(request, _resp_message(resp, "Utilisateur activé." if new_active else "Utilisateur désactivé."))
        log_event(request, "ADMIN_SET_ACTIVE_TRUE" if new_active else "ADMIN_SET_ACTIVE_FALSE")
    else:
        messages.error(request, _resp_message(resp, "Erreur lors de la mise à jour de l'utilisateur."))

    return redirect("admin_users_list")


@super_admin_required
def admin_reset_password(request, user_id: int):
    rid = get_request_id(request)

    if request.method == "POST":
        pwd1 = request.POST.get("password1") or ""
        pwd2 = request.POST.get("password2") or ""

        if not pwd1 or not pwd2:
            messages.error(request, "Veuillez remplir les deux champs.")
            return redirect("admin_reset_password", user_id=user_id)

        if pwd1 != pwd2:
            messages.error(request, "Les mots de passe ne correspondent pas.")
            return redirect("admin_reset_password", user_id=user_id)

        if len(pwd1) < 4:
            messages.error(request, "Le mot de passe doit contenir au moins 4 caractères.")
            return redirect("admin_reset_password", user_id=user_id)

        actor_id = int((request.session.get("user") or {}).get("id") or 0)
        resp = rmi_client.admin_reset_password(actor_id, int(user_id), pwd1, request_id=rid)
        log_rmi(request, "admin_reset_password", resp, actor_id=actor_id, target_user_id=user_id)

        if resp.get("success"):
            messages.success(request, _resp_message(resp, "Mot de passe réinitialisé."))
            log_event(request, "ADMIN_RESET_PASSWORD")
            return redirect("admin_users_list")

        messages.error(request, _resp_message(resp, "Erreur lors du reset password."))
        return redirect("admin_reset_password", user_id=user_id)

    return render(
        request,
        "accounts/admin_reset_password.html",
        {"user": request.session.get("user"), "target_user_id": user_id},
    )


@admin_required
def admin_client_accounts(request, client_id: int):
    rid = get_request_id(request)

    data = get_client_accounts(int(client_id), request_id=rid)
    log_rmi(request, "get_client_accounts(admin_client_accounts)", data, client_id=client_id)

    accounts = data.get("accounts", []) if data.get("success") else []

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur lors du chargement des comptes du client."))

    normalized = []
    for a in accounts:
        if isinstance(a, dict):
            if "number" not in a or not a.get("number"):
                a["number"] = a.get("account_number")
        normalized.append(a)

    return render(
        request,
        "accounts/admin_client_accounts.html",
        {"client_id": client_id, "accounts": normalized},
    )


@admin_required
def admin_close_account(request, account_number: str):
    rid = get_request_id(request)

    if request.method != "POST":
        return redirect("admin_users_list")

    resp = rmi_close_account(account_number, request_id=rid)
    log_rmi(request, "close_account(admin)", resp, account=account_number)

    if resp.get("success"):
        messages.success(request, _resp_message(resp, f"Compte {account_number} fermé avec succès."))
        log_event(request, "ADMIN_CLOSE_ACCOUNT")
    else:
        messages.error(request, _resp_message(resp, "Erreur lors de la fermeture du compte."))

    return _safe_next_redirect(request, "admin_users_list")


@staff_required
def admin_all_transactions(request):
    rid = get_request_id(request)

    data = rmi_get_all_transactions(request_id=rid)
    log_rmi(request, "get_all_transactions", data)

    txs = data.get("transactions", []) if data.get("success") else []

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur lors du chargement des transactions globales."))

    account_filter = (request.GET.get("account", "") or "").strip()
    type_filter = (request.GET.get("type", "ALL") or "ALL").upper()
    date_from_str = (request.GET.get("date_from", "") or "").strip()
    date_to_str = (request.GET.get("date_to", "") or "").strip()

    date_from = parse_date(date_from_str) if date_from_str else None
    date_to = parse_date(date_to_str) if date_to_str else None

    filtered = []
    for t in txs:
        ts = t.get("date")
        dt = None
        if ts:
            try:
                dt = datetime.fromtimestamp(ts / 1000.0)
            except Exception:
                dt = None

        acc = str(t.get("account") or "")
        t_type = (t.get("type") or "").upper()

        include = True
        if account_filter and account_filter not in acc:
            include = False
        if type_filter != "ALL" and t_type != type_filter:
            include = False

        if dt is not None:
            d = dt.date()
            if date_from and d < date_from:
                include = False
            if date_to and d > date_to:
                include = False

        if include:
            t["date_str"] = dt.strftime("%Y-%m-%d %H:%M") if dt else "-"
            filtered.append(t)

    paginator = Paginator(filtered, 50)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(
        request,
        "accounts/admin_all_transactions.html",
        {
            "user": request.session.get("user"),
            "transactions": page_obj,
            "page_obj": page_obj,
            "filters": {
                "account": account_filter,
                "type": type_filter,
                "date_from": date_from_str,
                "date_to": date_to_str,
            },
        },
    )


@staff_required
def admin_export_transactions_csv(request):
    rid = get_request_id(request)

    data = rmi_get_all_transactions(request_id=rid)
    log_rmi(request, "get_all_transactions(export_csv_admin)", data)

    txs = data.get("transactions", []) if data.get("success") else []

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur lors du chargement des transactions."))
        return redirect("admin_all_transactions")

    account_filter = (request.GET.get("account", "") or "").strip()
    type_filter = (request.GET.get("type", "ALL") or "ALL").upper()
    date_from_str = (request.GET.get("date_from", "") or "").strip()
    date_to_str = (request.GET.get("date_to", "") or "").strip()

    date_from = parse_date(date_from_str) if date_from_str else None
    date_to = parse_date(date_to_str) if date_to_str else None

    filtered = []
    for t in txs:
        ts = t.get("date")
        dt = None
        if ts:
            try:
                dt = datetime.fromtimestamp(ts / 1000.0)
            except Exception:
                dt = None

        acc = str(t.get("account") or "").strip()
        t_type = (t.get("type") or "").upper()

        include = True
        if account_filter and account_filter not in acc:
            include = False
        if type_filter != "ALL" and t_type != type_filter:
            include = False

        if dt is not None:
            d = dt.date()
            if date_from and d < date_from:
                include = False
            if date_to and d > date_to:
                include = False

        if include:
            filtered.append(t)

    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="admin_transactions.csv"'

    writer = csv.writer(resp)
    writer.writerow(["id", "account", "type", "amount", "balance_after", "date_ms", "branch_name"])

    for t in filtered:
        writer.writerow([
            t.get("id"),
            t.get("account"),
            t.get("type"),
            t.get("amount"),
            t.get("balance_after"),
            t.get("date"),
            t.get("branch_name"),
        ])

    return resp


@admin_required
def admin_export_clients_accounts_csv(request):
    rid = get_request_id(request)

    users_resp = rmi_list_users(request_id=rid)
    log_rmi(request, "list_users(export_clients_accounts)", users_resp)

    if not users_resp.get("success"):
        messages.error(request, _resp_message(users_resp, "Erreur récupération users."))
        return redirect("admin_users_list")

    users = users_resp.get("users", [])
    client_users = [u for u in users if (u.get("role") or "").upper() == "CLIENT" and u.get("client_id") is not None]

    rows = []
    for u in client_users:
        cid = u.get("client_id")
        acc = get_client_accounts(int(cid), request_id=rid)
        log_rmi(request, "get_client_accounts(export_clients_accounts)", acc, client_id=cid)

        if not acc.get("success"):
            rows.append([cid, u.get("username"), "", "", _resp_message(acc, "ERROR")])
            continue

        for a in acc.get("accounts", []):
            rows.append([cid, u.get("username"), a.get("number") or a.get("account_number"), a.get("balance"), ""])

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="clients_accounts.csv"'
    writer = csv.writer(response)
    writer.writerow(["client_id", "username", "account_number", "balance", "note"])
    for r in rows:
        writer.writerow(r)

    return response


@admin_required
def admin_clients_list(request):
    rid = get_request_id(request)

    resp = rmi_list_users(request_id=rid)
    log_rmi(request, "list_users(clients_list)", resp)

    users = resp.get("users", []) if resp.get("success") else []
    clients = [u for u in users if (u.get("role") or "").upper() == "CLIENT" and u.get("client_id") is not None]

    if not resp.get("success"):
        messages.error(request, _resp_message(resp, "Erreur lors du chargement des clients."))

    return render(request, "accounts/admin_clients_list.html", {"user": request.session.get("user"), "clients": clients})


@staff_required
def admin_security_journal(request):
    from django.db.models import Q

    q = (request.GET.get("q") or "").strip()
    date_from = (request.GET.get("date_from") or "").strip()
    date_to = (request.GET.get("date_to") or "").strip()

    logs = AuditLog.objects.all().order_by("-created_at")

    if q:
        logs = logs.filter(Q(action__icontains=q) | Q(ip_address__icontains=q))

    if date_from:
        logs = logs.filter(created_at__date__gte=date_from)
    if date_to:
        logs = logs.filter(created_at__date__lte=date_to)

    paginator = Paginator(logs, 50)
    page_obj = paginator.get_page(request.GET.get("page"))

    log_info(request, "SECURITY_JOURNAL_VIEW", q=q, date_from=date_from, date_to=date_to)

    return render(
        request,
        "accounts/admin_security_journal.html",
        {
            "user": request.session.get("user"),
            "page_obj": page_obj,
            "logs": page_obj,
            "filters": {"q": q, "date_from": date_from, "date_to": date_to},
        },
    )


@login_required
def my_account_view(request):
    user = request.session.get("user") or {}
    user_id = user.get("id")
    rid = get_request_id(request)

    if not user_id:
        messages.error(request, "Session invalide.")
        return redirect("login")

    prof_resp = rmi_get_user_profile(int(user_id), request_id=rid)
    log_rmi(request, "get_user_profile", prof_resp, user_id=user_id)

    profile = {}
    if prof_resp.get("success"):
        profile = prof_resp.get("profile", {}) or {}
    else:
        messages.error(request, _resp_message(prof_resp, "Impossible de charger le profil."))

    if request.method == "POST":
        username = (request.POST.get("username") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name = (request.POST.get("last_name") or "").strip()
        email = (request.POST.get("email") or "").strip()
        phone = (request.POST.get("phone") or "").strip()
        address = (request.POST.get("address") or "").strip()

        upd = rmi_update_user_profile(
            int(user_id),
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            address=address,
            request_id=rid,
        )
        log_rmi(request, "update_user_profile", upd, user_id=user_id)

        if upd.get("success"):
            request.session["user"]["username"] = username
            messages.success(request, _resp_message(upd, "Informations mises à jour."))
            log_event(request, "MY_ACCOUNT_UPDATE")
            return redirect("my_account")

        messages.error(request, _resp_message(upd, "Échec mise à jour."))

        prof_resp = rmi_get_user_profile(int(user_id), request_id=rid)
        if prof_resp.get("success"):
            profile = prof_resp.get("profile", {}) or {}

    return render(request, "accounts/my_account.html", {"user": user, "profile": profile})


@staff_required
def admin_stats_view(request):
    rid = get_request_id(request)

    resp = rmi_client.get_admin_stats(request_id=rid)
    log_rmi(request, "admin_stats", resp)

    stats = resp.get("stats", {}) if resp.get("success") else {}

    if not resp.get("success"):
        messages.error(request, _resp_message(resp, "Erreur lors du chargement des statistiques globales."))

    def safe_avg(total, count):
        try:
            if not total or not count:
                return None
            return float(total) / float(count)
        except Exception:
            return None

    stats["avg_deposits"] = safe_avg(stats.get("total_deposits_amount"), stats.get("total_deposits_count"))
    stats["avg_withdrawals"] = safe_avg(stats.get("total_withdrawals_amount"), stats.get("total_withdrawals_count"))
    stats["avg_transfers"] = safe_avg(stats.get("total_transfers_amount"), stats.get("total_transfers_count"))

    date_from_str = (request.GET.get("date_from", "") or "").strip()
    date_to_str = (request.GET.get("date_to", "") or "").strip()

    date_from = parse_date(date_from_str) if date_from_str else None
    date_to = parse_date(date_to_str) if date_to_str else None

    tx_data = rmi_get_all_transactions(request_id=rid)
    log_rmi(request, "get_all_transactions(stats_period)", tx_data)

    all_txs = tx_data.get("transactions", []) if tx_data.get("success") else []

    if not tx_data.get("success"):
        messages.error(request, _resp_message(tx_data, "Erreur lors du chargement des transactions pour les stats."))

    period_txs = []
    for t in all_txs:
        ts = t.get("date")
        dt = None
        if ts:
            try:
                dt = datetime.fromtimestamp(ts / 1000.0)
            except Exception:
                dt = None

        if dt is not None:
            d = dt.date()
            if date_from and d < date_from:
                continue
            if date_to and d > date_to:
                continue

        period_txs.append(t)

    period_stats = {
        "total_transactions": len(period_txs),
        "total_amount": 0.0,
        "by_type": {
            "DEPOSIT": {"count": 0, "sum": 0.0, "avg": 0.0},
            "WITHDRAWAL": {"count": 0, "sum": 0.0, "avg": 0.0},
            "TRANSFER": {"count": 0, "sum": 0.0, "avg": 0.0},
        },
    }

    for t in period_txs:
        typ = (t.get("type") or "").upper()
        amt = float(t.get("amount") or 0.0)
        period_stats["total_amount"] += amt
        if typ in period_stats["by_type"]:
            period_stats["by_type"][typ]["count"] += 1
            period_stats["by_type"][typ]["sum"] += amt

    for typ, obj in period_stats["by_type"].items():
        obj["avg"] = (obj["sum"] / obj["count"]) if obj["count"] > 0 else 0.0

    branch_period_stats: Dict[str, Dict[str, float]] = {}
    for t in period_txs:
        branch_name = t.get("branch_name") or "Inconnue"
        amt = float(t.get("amount") or 0.0)
        bp = branch_period_stats.setdefault(branch_name, {"transactions_count": 0, "total_amount": 0.0})
        bp["transactions_count"] += 1
        bp["total_amount"] += amt

    chart_labels = ["DEPOSIT", "WITHDRAWAL", "TRANSFER"]
    chart_values = [
        period_stats["by_type"]["DEPOSIT"]["sum"],
        period_stats["by_type"]["WITHDRAWAL"]["sum"],
        period_stats["by_type"]["TRANSFER"]["sum"],
    ]

    branch_labels = list(branch_period_stats.keys())
    branch_values = [v["total_amount"] for v in branch_period_stats.values()]

    return render(
        request,
        "accounts/admin_stats.html",
        {
            "user": request.session.get("user"),
            "stats": stats,
            "period": {"date_from": date_from_str, "date_to": date_to_str},
            "period_stats": period_stats,
            "branch_period_stats": branch_period_stats,
            "chart_labels_json": chart_labels,
            "chart_values_json": chart_values,
            "branch_labels_json": branch_labels,
            "branch_values_json": branch_values,
        },
    )

admin_stats = admin_stats_view


@admin_required
def admin_set_client_type(request, client_id: int):
    rid = get_request_id(request)

    if request.method != "POST":
        return redirect("admin_clients_list")

    client_type = (request.POST.get("client_type") or "").strip().upper()
    if client_type not in {"STANDARD", "VIP"}:
        messages.error(request, "Type invalide (STANDARD/VIP).")
        return redirect("admin_clients_list")

    resp = rmi_client.set_client_type(int(client_id), client_type, request_id=rid)
    log_rmi(request, "set_client_type", resp, client_id=client_id, client_type=client_type)

    if resp.get("success"):
        messages.success(request, _resp_message(resp, f"Type client mis à jour: {client_type}"))
        log_event(request, "ADMIN_SET_CLIENT_TYPE")
    else:
        messages.error(request, _resp_message(resp, "Échec mise à jour type client."))

    return redirect("admin_clients_list")


@login_required
def account_details_view(request, account_number: str):
    rid = get_request_id(request)

    if not _ensure_account_owned(request, account_number):
        messages.error(request, "Accès refusé : ce compte ne vous appartient pas.")
        return redirect("dashboard")

    user = request.session.get("user") or {}
    client_id = user.get("client_id")

    if client_id is None:
        messages.error(request, "Session invalide (client_id manquant).")
        return redirect("dashboard")

    data = get_client_accounts(int(client_id), request_id=rid)
    log_rmi(request, "get_client_accounts(account_details)", data, client_id=client_id, account=account_number)

    if not data.get("success"):
        messages.error(request, _resp_message(data, "Erreur lors du chargement du compte."))
        return redirect("dashboard")

    account: Optional[Dict[str, Any]] = None
    for a in data.get("accounts", []):
        num = a.get("number") or a.get("account_number")
        if str(num) == str(account_number):
            account = a
            break

    if not account:
        messages.error(request, "Compte introuvable.")
        return redirect("dashboard")

    limits_resp = rmi_client.get_limits(account_number, request_id=rid)
    log_rmi(request, "get_limits", limits_resp, account=account_number)

    limits_data = limits_resp.get("data") if limits_resp.get("success") else None

    if limits_resp and not limits_resp.get("success"):
        messages.warning(request, _resp_message(limits_resp, "Impossible de récupérer les plafonds."))

    return render(
        request,
        "accounts/account_details.html",
        {
            "user": user,
            "account": account,
            "limits": limits_data,
        },
    )
@super_admin_required
def admin_delete_user(request, user_id: int):
    if request.method != "POST":
        messages.error(request, "Méthode non autorisée (POST requis).")
        return redirect("admin_users_list")

    actor_id = int((request.session.get("user") or {}).get("id") or 0)

    if actor_id == int(user_id):
        messages.error(request, "Vous ne pouvez pas supprimer votre propre compte.")
        return redirect("admin_users_list")

    resp = rmi_client.delete_user(actor_id, int(user_id))
    log_rmi(request, "delete_user", resp, actor_id=actor_id, target_user_id=user_id)

    if resp.get("success"):
        messages.success(request, _resp_message(resp, "Utilisateur supprimé définitivement."))
        log_event(request, "ADMIN_DELETE_USER")
    else:
        messages.error(request, _resp_message(resp, "Échec suppression utilisateur."))

    return redirect("admin_users_list")
