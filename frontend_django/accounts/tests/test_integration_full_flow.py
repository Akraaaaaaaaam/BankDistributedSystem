import json
import os
import subprocess
from pathlib import Path
from django.test import TransactionTestCase
from django.urls import reverse


class FullIntegrationFlowTest(TransactionTestCase):

    DJANGO_LOGIN_USER = "Ali"
    DJANGO_LOGIN_PASS = "Ali2004"

    ACC1 = "ACC-002-0001-001"
    ACC2 = "ACC-002-0001-002"

    JAVA_MAIN = "ma.fsa.bank.client.RmiClient"
    RMI_HOST = os.environ.get("BANK_RMI_HOST", "localhost")
    RMI_PORT = os.environ.get("BANK_RMI_PORT", "1099")

    BASE_DIR = Path(__file__).resolve().parents[3]
    BACKEND_DIR = BASE_DIR / "backend_rmi"
    CLASSES_DIR = BACKEND_DIR / "build" / "classes"
    JAR_PATH = BACKEND_DIR / "lib" / "mysql-connector-j-9.5.0.jar"

    JAVA_CP = f"{CLASSES_DIR};{JAR_PATH}"

    def _run_rmicli(self, *args, timeout=10) -> dict:
        cmd = ["java", "-cp", self.JAVA_CP, self.JAVA_MAIN, *map(str, args)]

        env = os.environ.copy()
        env["BANK_RMI_HOST"] = self.RMI_HOST
        env["BANK_RMI_PORT"] = str(self.RMI_PORT)

        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=str(self.BASE_DIR),
        )

        out = (p.stdout or "").strip()
        if not out:
            raise AssertionError(f"RmiClient stdout vide. stderr={p.stderr}")

        try:
            return json.loads(out)
        except Exception:
            raise AssertionError(f"JSON invalide depuis RmiClient: {out}")

    def _assert_success(self, res: dict, context: str):
        # Ton contrat JSON utilise 'success' (pas 'ok')
        self.assertTrue(res.get("success") is True, msg=f"{context} KO: {res}")

    def _get_balance(self, account_number: str) -> float:
        res = self._run_rmicli("get_balance", account_number)
        self._assert_success(res, "get_balance")
        return float(res["data"]["balance"])

    def setUp(self):
        resp = self.client.post(
            reverse("login"),
            {"username": self.DJANGO_LOGIN_USER, "password": self.DJANGO_LOGIN_PASS},
            follow=False,
        )
        self.assertIn(resp.status_code, (302, 303), msg=f"Login échoué: {resp.status_code}")

        session = self.client.session
        session["otp_verified"] = True
        session["otp_required"] = False
        session.save()

    def test_full_flow_deposit_withdraw_transfer_transactions_csv(self):
        # 1) Soldes init (via RmiClient)
        b1_before = self._get_balance(self.ACC1)
        b2_before = self._get_balance(self.ACC2)

        # 2) Dépôt via Django
        resp = self.client.post(
            reverse("deposit"),
            {"account_number": self.ACC1, "amount": "100"},
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)

        b1_after_deposit = self._get_balance(self.ACC1)
        self.assertGreaterEqual(
            b1_after_deposit,
            b1_before + 100,
            msg=f"Solde après dépôt inattendu: before={b1_before}, after={b1_after_deposit}",
            )

        # 3) Retrait via Django
        resp = self.client.post(
            reverse("withdraw"),
            {"account_number": self.ACC1, "amount": "50"},
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)

        b1_after_withdraw = self._get_balance(self.ACC1)
        self.assertLessEqual(
            b1_after_withdraw,
            b1_after_deposit - 50,
            msg=f"Solde après retrait inattendu: before={b1_after_deposit}, after={b1_after_withdraw}",
            )

        resp = self.client.post(
            reverse("transfer"),
            {"from_account": self.ACC1, "to_account": self.ACC2, "amount": "30"},
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)

        b1_after_transfer = self._get_balance(self.ACC1)
        b2_after_transfer = self._get_balance(self.ACC2)

        self.assertLessEqual(
            b1_after_transfer,
            b1_after_withdraw - 30,
            msg=f"Solde ACC1 après virement inattendu: {b1_after_transfer}",
            )
        self.assertGreaterEqual(
            b2_after_transfer,
            b2_before + 30,
            msg=f"Solde ACC2 après virement inattendu: before={b2_before}, after={b2_after_transfer}",
            )

        resp = self.client.get(reverse("transactions", args=[self.ACC1]))
        self.assertEqual(resp.status_code, 200)

        resp = self.client.get(reverse("export_transactions_csv", args=[self.ACC1]))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.get("Content-Type", ""))
