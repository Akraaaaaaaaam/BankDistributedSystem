from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register_view, name="register"),
    path("otp/", views.otp_verify_view, name="otp_verify"),
    path("my-account/", views.my_account_view, name="my_account"),
    path("admin/users/<int:user_id>/reset-password/", views.admin_reset_password, name="admin_reset_password"),
    path("admin/users/<int:user_id>/delete/", views.admin_delete_user, name="admin_delete_user"),
    path("", views.dashboard, name="dashboard"),
    path("deposit/", views.deposit_view, name="deposit"),
    path("withdraw/", views.withdraw_view, name="withdraw"),
    path("transfer/", views.transfer_view, name="transfer"),
    path("create-account/", views.create_account_view, name="create_account"),
    path("transactions/<str:account_number>/", views.transactions_view, name="transactions"),
    path(
        "account/<str:account_number>/details/",
        views.account_details_view,
        name="account_details"
    ),
    path("transactions/<str:account_number>/export/csv/", views.export_transactions_csv, name="export_transactions_csv"),
    path("admin/users/", views.admin_users_list, name="admin_users_list"),
    path("admin/users/create/", views.admin_create_admin, name="admin_create_admin"),
    path("admin/users/<int:user_id>/set-active/", views.admin_set_user_active, name="admin_set_user_active"),

    path("admin/stats/", views.admin_stats_view, name="admin_stats"),
    path("admin/transactions/", views.admin_all_transactions, name="admin_all_transactions"),

    path("admin/transactions/export/csv/", views.admin_export_transactions_csv, name="admin_export_transactions_csv"),
    path("admin/clients/export/csv/", views.admin_export_clients_accounts_csv, name="admin_export_clients_accounts_csv"),

    path("admin/client/<int:client_id>/accounts/", views.admin_client_accounts, name="admin_client_accounts"),
    path("admin/accounts/<str:account_number>/close/", views.admin_close_account, name="admin_close_account"),

    path("admin/security/", views.admin_security_journal, name="admin_security_journal"),

    path("admin/clients/", views.admin_clients_list, name="admin_clients_list"),
    path("admin/clients/<int:client_id>/set-type/", views.admin_set_client_type, name="admin_set_client_type"),
]
