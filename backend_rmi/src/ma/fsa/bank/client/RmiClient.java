package ma.fsa.bank.client;

import ma.fsa.bank.common.dto.*;
import ma.fsa.bank.rmi.interfaces.BankService;

import java.rmi.ConnectIOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.List;
import java.util.UUID;

public class RmiClient {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 1099;
    private static final String DEFAULT_BINDING = "BankService";

    public static void main(String[] args) {
        final String requestId = UUID.randomUUID().toString();

        if (args == null || args.length < 1) {
            printErr(requestId, "No command provided", "INVALID_ARGS", null);
            return;
        }

        String command = args[0];

        try {
            String host = getEnvOrDefault("BANK_RMI_HOST", DEFAULT_HOST);
            int port = parseIntSafe(getEnvOrDefault("BANK_RMI_PORT", String.valueOf(DEFAULT_PORT)), DEFAULT_PORT);

            Registry registry = LocateRegistry.getRegistry(host, port);
            BankService service = (BankService) registry.lookup(DEFAULT_BINDING);

            switch (command) {
                case "delete_user": {
                    requireArgs(args, 3, "Usage: delete_user <actorUserId> <targetUserId>");
                    int actorId = parseIntStrict(args[1], "actorUserId");
                    int targetId = parseIntStrict(args[2], "targetUserId");

                    boolean ok = service.adminDeleteUser(actorId, targetId);
                    if (ok) printOk(requestId, "User deleted", "{\"ok\":true}");
                    else printErr(requestId, "Delete user failed", "OP_FAILED", null);
                    break;
                }

                case "withdraw": {
                    requireArgs(args, 3, "Usage: withdraw <accountNumber> <amount>");
                    String acc = args[1];
                    double amount = parseDoubleStrict(args[2], "amount");

                    boolean ok = service.withdraw(acc, amount);
                    if (ok) printOk(requestId, "Withdrawal OK", "{\"ok\":true}");
                    else printErr(requestId, "Withdrawal failed", "OP_FAILED", null);
                    break;
                }

                case "deposit": {
                    requireArgs(args, 3, "Usage: deposit <accountNumber> <amount>");
                    String acc = args[1];
                    double amount = parseDoubleStrict(args[2], "amount");

                    boolean ok = service.deposit(acc, amount);
                    if (ok) printOk(requestId, "Deposit OK", "{\"ok\":true}");
                    else printErr(requestId, "Deposit failed", "OP_FAILED", null);
                    break;
                }

                case "transfer": {
                    requireArgs(args, 4, "Usage: transfer <fromAccountNumber> <toAccountNumber> <amount>");
                    String fromAcc = args[1];
                    String toAcc = args[2];
                    double amount = parseDoubleStrict(args[3], "amount");

                    boolean ok = service.transfer(fromAcc, toAcc, amount);
                    if (ok) printOk(requestId, "Transfer OK", "{\"ok\":true}");
                    else printErr(requestId, "Transfer failed", "OP_FAILED", null);
                    break;
                }

                case "get_balance": {
                    requireArgs(args, 2, "Usage: get_balance <accountNumber>");
                    String accountNumber = args[1];
                    double balance = service.getBalance(accountNumber);

                    String data = "{"
                            + "\"account\":\"" + escapeJson(accountNumber) + "\","
                            + "\"balance\":" + balance
                            + "}";
                    printOk(requestId, "Balance OK", data);
                    break;
                }

                case "get_client_accounts": {
                    requireArgs(args, 2, "Usage: get_client_accounts <clientId>");
                    int clientId = parseIntStrict(args[1], "clientId");

                    List<AccountDTO> accounts = service.getClientAccounts(clientId);

                    StringBuilder sb = new StringBuilder(256);
                    sb.append("{\"client_id\":").append(clientId).append(",\"accounts\":[");
                    for (int i = 0; i < accounts.size(); i++) {
                        AccountDTO acc = accounts.get(i);
                        sb.append("{\"id\":").append(acc.getId())
                                .append(",\"number\":\"").append(escapeJson(nz(acc.getAccountNumber()))).append("\"")
                                .append(",\"balance\":").append(acc.getBalance())
                                .append(",\"type\":\"").append(escapeJson(nz(acc.getType()))).append("\"")
                                .append(",\"currency\":\"").append(escapeJson(nz(acc.getCurrency()))).append("\"")
                                .append(",\"status\":\"").append(escapeJson(nz(acc.getStatus()))).append("\"")
                                .append(",\"branch_name\":\"").append(escapeJson(nz(acc.getBranchName()))).append("\"")
                                .append("}");
                        if (i < accounts.size() - 1) sb.append(",");
                    }
                    sb.append("]}");

                    printOk(requestId, "Accounts OK", sb.toString());
                    break;
                }

                case "get_transactions": {
                    requireArgs(args, 2, "Usage: get_transactions <accountNumber>");
                    String acc = args[1];

                    List<TransactionDTO> txs = service.getTransactions(acc);

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"account\":\"").append(escapeJson(acc)).append("\",\"transactions\":[");
                    for (int i = 0; i < txs.size(); i++) {
                        TransactionDTO t = txs.get(i);
                        sb.append("{\"id\":").append(t.getId())
                                .append(",\"type\":\"").append(escapeJson(nz(t.getType()))).append("\"")
                                .append(",\"amount\":").append(t.getAmount())
                                .append(",\"balance_after\":").append(t.getBalanceAfter())
                                .append(",\"date\":").append(t.getDate() != null ? t.getDate().getTime() : 0)
                                .append("}");
                        if (i < txs.size() - 1) sb.append(",");
                    }
                    sb.append("]}");

                    printOk(requestId, "Transactions OK", sb.toString());
                    break;
                }

                case "register": {
                    requireArgs(args, 10, "Usage: register <username> <password> <branchId> <firstName> <lastName> <cin> <email|-> <phone|-> <address|->");

                    String username = args[1];
                    String password = args[2];
                    int branchId = parseIntStrict(args[3], "branchId");
                    String firstName = args[4];
                    String lastName  = args[5];
                    String cin       = args[6];
                    String email     = args[7];
                    String phone     = args[8];
                    String address   = args[9];

                    RegisterRequest req = new RegisterRequest(username, password, branchId, firstName, lastName, cin, email, phone, address);
                    RegisterResponse resp = service.registerUser(req);

                    if (resp != null && resp.isSuccess()) {
                        String data = "{"
                                + "\"registered\":true,"
                                + "\"server_message\":\"" + escapeJson(nz(resp.getMessage())) + "\""
                                + "}";
                        printOk(requestId, "Register OK", data);
                    } else {
                        String msg = (resp == null) ? "Register failed" : nz(resp.getMessage());
                        printErr(requestId, msg, "REGISTER_FAILED", null);
                    }
                    break;
                }

                case "login": {
                    requireArgs(args, 3, "Usage: login <username> <password>");
                    String username = args[1];
                    String password = args[2];

                    UserDTO user = service.authenticate(username, password);
                    if (user == null) {
                        printErr(requestId, "Invalid credentials", "AUTH_FAILED", null);
                    } else {
                        String clientIdPart = (user.getClientId() == null) ? "null" : String.valueOf(user.getClientId());
                        String data = "{"
                                + "\"id\":" + user.getId() + ","
                                + "\"client_id\":" + clientIdPart + ","
                                + "\"username\":\"" + escapeJson(nz(user.getUsername())) + "\","
                                + "\"role\":\"" + escapeJson(nz(user.getRole())) + "\","
                                + "\"active\":" + user.isActive() + ","
                                + "\"is_super_admin\":" + user.isSuperAdmin() + ","
                                + "\"created_by\":" + (user.getCreatedBy() == null ? "null" : user.getCreatedBy())
                                + "}";
                        printOk(requestId, "Login OK", data);
                    }
                    break;
                }

                case "create_account": {
                    requireArgs(args, 5, "Usage: create_account <clientId> <branchId> <type> <currency>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    int branchId = parseIntStrict(args[2], "branchId");
                    String type = args[3];
                    String currency = args[4];

                    AccountDTO acc = service.createAccount(clientId, branchId, type, currency);
                    if (acc == null) {
                        printErr(requestId, "Create account failed", "OP_FAILED", null);
                        break;
                    }

                    String data = "{"
                            + "\"id\":" + acc.getId() + ","
                            + "\"number\":\"" + escapeJson(nz(acc.getAccountNumber())) + "\","
                            + "\"balance\":" + acc.getBalance() + ","
                            + "\"type\":\"" + escapeJson(nz(acc.getType())) + "\","
                            + "\"currency\":\"" + escapeJson(nz(acc.getCurrency())) + "\","
                            + "\"status\":\"" + escapeJson(nz(acc.getStatus())) + "\","
                            + "\"branch_name\":\"" + escapeJson(nz(acc.getBranchName())) + "\""
                            + "}";
                    printOk(requestId, "Create account OK", data);
                    break;
                }

                case "close_account": {
                    requireArgs(args, 2, "Usage: close_account <accountNumber>");
                    String accountNumber = args[1];
                    boolean ok = service.closeAccount(accountNumber);

                    if (ok) printOk(requestId, "Close account OK", "{\"ok\":true}");
                    else printErr(requestId, "Close account failed", "OP_FAILED", null);
                    break;
                }

                case "list_users": {
                    List<UserDTO> users = service.listUsers();

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"users\":[");
                    for (int i = 0; i < users.size(); i++) {
                        UserDTO u = users.get(i);
                        String clientIdPart = (u.getClientId() == null) ? "null" : String.valueOf(u.getClientId());
                        String createdByPart = (u.getCreatedBy() == null) ? "null" : String.valueOf(u.getCreatedBy());

                        sb.append("{\"id\":").append(u.getId())
                                .append(",\"client_id\":").append(clientIdPart)
                                .append(",\"username\":\"").append(escapeJson(nz(u.getUsername()))).append("\"")
                                .append(",\"role\":\"").append(escapeJson(nz(u.getRole()))).append("\"")
                                .append(",\"active\":").append(u.isActive())
                                .append(",\"is_super_admin\":").append(u.isSuperAdmin())
                                .append(",\"created_by\":").append(createdByPart)
                                .append("}");
                        if (i < users.size() - 1) sb.append(",");
                    }
                    sb.append("]}");

                    printOk(requestId, "Users OK", sb.toString());
                    break;
                }

                case "create_admin": {
                    requireArgs(args, 3, "Usage: create_admin <username> <password>");
                    String username = args[1];
                    String password = args[2];

                    UserDTO admin = service.createAdminUser(username, password);
                    if (admin == null) {
                        printErr(requestId, "Create admin failed", "OP_FAILED", null);
                        break;
                    }

                    String clientIdPart = (admin.getClientId() == null) ? "null" : String.valueOf(admin.getClientId());
                    String createdByPart = (admin.getCreatedBy() == null) ? "null" : String.valueOf(admin.getCreatedBy());

                    String data = "{"
                            + "\"id\":" + admin.getId() + ","
                            + "\"client_id\":" + clientIdPart + ","
                            + "\"username\":\"" + escapeJson(nz(admin.getUsername())) + "\","
                            + "\"role\":\"" + escapeJson(nz(admin.getRole())) + "\","
                            + "\"active\":" + admin.isActive() + ","
                            + "\"is_super_admin\":" + admin.isSuperAdmin() + ","
                            + "\"created_by\":" + createdByPart
                            + "}";
                    printOk(requestId, "Create admin OK", data);
                    break;
                }

                case "admin_reset_password": {
                    requireArgs(args, 4, "Usage: admin_reset_password <actorUserId> <targetUserId> <newPassword>");
                    int actorId = parseIntStrict(args[1], "actorUserId");
                    int targetId = parseIntStrict(args[2], "targetUserId");
                    String newPass = args[3];

                    boolean ok = service.adminResetPassword(actorId, targetId, newPass);
                    if (ok) printOk(requestId, "Reset password OK", "{\"ok\":true}");
                    else printErr(requestId, "Reset password failed", "OP_FAILED", null);
                    break;
                }

                case "admin_stats": {
                    AdminGlobalStatsDTO s = service.getAdminGlobalStats();
                    if (s == null) {
                        printErr(requestId, "Stats not available", "OP_FAILED", null);
                        break;
                    }

                    String statsObj = "{"
                            + "\"total_users\":" + s.getTotalUsers() + ","
                            + "\"total_clients\":" + s.getTotalClients() + ","
                            + "\"total_admins\":" + s.getTotalAdmins() + ","
                            + "\"total_branches\":" + s.getTotalBranches() + ","
                            + "\"active_accounts\":" + s.getActiveAccounts() + ","
                            + "\"closed_accounts\":" + s.getClosedAccounts() + ","
                            + "\"total_transactions\":" + s.getTotalTransactions() + ","
                            + "\"total_deposits_count\":" + s.getTotalDepositsCount() + ","
                            + "\"total_deposits_amount\":" + s.getTotalDepositsAmount() + ","
                            + "\"total_withdrawals_count\":" + s.getTotalWithdrawalsCount() + ","
                            + "\"total_withdrawals_amount\":" + s.getTotalWithdrawalsAmount() + ","
                            + "\"total_transfers_count\":" + s.getTotalTransfersCount() + ","
                            + "\"total_transfers_amount\":" + s.getTotalTransfersAmount()
                            + "}";

                    String data = "{\"stats\":" + statsObj + "}";
                    printOk(requestId, "Stats OK", data);
                    break;
                }

                case "set_user_active": {
                    requireArgs(args, 3, "Usage: set_user_active <userId> <true|false>");
                    int userId = parseIntStrict(args[1], "userId");
                    boolean active = Boolean.parseBoolean(args[2]);

                    boolean ok = service.setUserActive(userId, active);
                    if (ok) {
                        String data = "{\"ok\":true,\"user_id\":" + userId + ",\"active\":" + active + "}";
                        printOk(requestId, "User updated", data);
                    } else {
                        printErr(requestId, "Update user failed", "OP_FAILED", null);
                    }
                    break;
                }

                case "get_all_transactions": {
                    List<TransactionDTO> list = service.getAllTransactions();

                    StringBuilder sb = new StringBuilder(1024);
                    sb.append("{\"transactions\":[");
                    for (int i = 0; i < list.size(); i++) {
                        TransactionDTO t = list.get(i);
                        sb.append("{\"id\":").append(t.getId())
                                .append(",\"account\":\"").append(escapeJson(nz(t.getAccountNumber()))).append("\"")
                                .append(",\"type\":\"").append(escapeJson(nz(t.getType()))).append("\"")
                                .append(",\"amount\":").append(t.getAmount())
                                .append(",\"balance_after\":").append(t.getBalanceAfter())
                                .append(",\"date\":").append(t.getDate() != null ? t.getDate().getTime() : 0)
                                .append(",\"branch_name\":\"").append(escapeJson(nz(t.getBranchName()))).append("\"")
                                .append("}");
                        if (i < list.size() - 1) sb.append(",");
                    }
                    sb.append("]}");

                    printOk(requestId, "All transactions OK", sb.toString());
                    break;
                }

                case "list_branches": {
                    List<BranchDTO> branches = service.listBranches();

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"branches\":[");
                    for (int i = 0; i < branches.size(); i++) {
                        BranchDTO b = branches.get(i);
                        sb.append("{\"id\":").append(b.getId())
                                .append(",\"code\":\"").append(escapeJson(nz(b.getCode()))).append("\"")
                                .append(",\"name\":\"").append(escapeJson(nz(b.getName()))).append("\"")
                                .append(",\"city\":\"").append(escapeJson(nz(b.getCity()))).append("\"")
                                .append("}");
                        if (i < branches.size() - 1) sb.append(",");
                    }
                    sb.append("]}");

                    printOk(requestId, "Branches OK", sb.toString());
                    break;
                }

                case "get_client_type": {
                    requireArgs(args, 2, "Usage: get_client_type <clientId>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    String type = service.getClientType(clientId);

                    String data = "{\"client_id\":" + clientId + ",\"client_type\":\"" + escapeJson(nz(type)) + "\"}";
                    printOk(requestId, "Client type OK", data);
                    break;
                }

                case "set_client_type": {
                    requireArgs(args, 3, "Usage: set_client_type <clientId> <STANDARD|VIP|PREMIUM|ENTREPRISE|ETUDIANT>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    String type = args[2];

                    boolean ok = service.setClientType(clientId, type);

                    if (ok) {
                        String data = "{"
                                + "\"client_id\":" + clientId + ","
                                + "\"client_type\":\"" + escapeJson(type) + "\""
                                + "}";
                        printOk(requestId, "Client type updated", data);
                    } else {
                        printErr(requestId, "Update client type failed", "OP_FAILED", null);
                    }
                    break;
                }

                case "get_limits": {
                    requireArgs(args, 2, "Usage: get_limits <accountNumber>");
                    String acc = args[1];
                    AccountLimitsDTO lim = service.getAccountLimits(acc);

                    if (lim == null) {
                        printErr(requestId, "Limits not found", "NOT_FOUND", null);
                        break;
                    }

                    String data = "{"
                            + "\"account\":\"" + escapeJson(nz(lim.getAccountNumber())) + "\","
                            + "\"client_type\":\"" + escapeJson(nz(lim.getClientType())) + "\","
                            + "\"daily_transfer_limit\":" + lim.getDailyTransferLimit() + ","
                            + "\"daily_debit_limit\":" + lim.getDailyDebitLimit()
                            + "}";

                    printOk(requestId, "Limits OK", data);
                    break;
                }

                case "get_user_profile": {
                    requireArgs(args, 2, "Usage: get_user_profile <userId>");
                    int userId = parseIntStrict(args[1], "userId");

                    UserProfileDTO p = service.getUserProfile(userId);
                    if (p == null) {
                        printErr(requestId, "User not found", "NOT_FOUND", null);
                        break;
                    }

                    String clientIdPart = (p.getClientId() == null) ? "null" : String.valueOf(p.getClientId());

                    String profileObj = "{"
                            + "\"id\":" + p.getId() + ","
                            + "\"client_id\":" + clientIdPart + ","
                            + "\"username\":\"" + escapeJson(nz(p.getUsername())) + "\","
                            + "\"role\":\"" + escapeJson(nz(p.getRole())) + "\","
                            + "\"active\":" + p.isActive() + ","
                            + "\"first_name\":\"" + escapeJson(nz(p.getFirstName())) + "\","
                            + "\"last_name\":\"" + escapeJson(nz(p.getLastName())) + "\","
                            + "\"cin\":\"" + escapeJson(nz(p.getCin())) + "\","
                            + "\"email\":\"" + escapeJson(nz(p.getEmail())) + "\","
                            + "\"phone\":\"" + escapeJson(nz(p.getPhone())) + "\","
                            + "\"address\":\"" + escapeJson(nz(p.getAddress())) + "\","
                            + "\"client_type\":\"" + escapeJson(nz(p.getClientType())) + "\""
                            + "}";

                    String data = "{\"profile\":" + profileObj + "}";
                    printOk(requestId, "Profile OK", data);
                    break;
                }

                case "update_user_profile": {
                    requireArgs(args, 8, "Usage: update_user_profile <userId> <username> <first_name> <last_name> <email> <phone> <address>");
                    int userId = parseIntStrict(args[1], "userId");
                    String username = args[2];
                    String firstName = args[3];
                    String lastName = args[4];
                    String email = args[5];
                    String phone = args[6];

                    StringBuilder addr = new StringBuilder();
                    for (int i = 7; i < args.length; i++) {
                        if (i > 7) addr.append(" ");
                        addr.append(args[i]);
                    }
                    String address = addr.toString();

                    if ("-".equals(firstName)) firstName = null;
                    if ("-".equals(lastName)) lastName = null;
                    if ("-".equals(email)) email = null;
                    if ("-".equals(phone)) phone = null;
                    if ("-".equals(address)) address = null;

                    UserProfileUpdateDTO upd = new UserProfileUpdateDTO(userId, username, firstName, lastName, email, phone, address);
                    boolean ok = service.updateUserProfile(upd);

                    if (ok) printOk(requestId, "Profile updated", "{\"ok\":true}");
                    else printErr(requestId, "Update profile failed", "OP_FAILED", null);
                    break;
                }

                default:
                    printErr(requestId, "Unknown command: " + command, "UNKNOWN_COMMAND", null);
            }

        } catch (IllegalArgumentException e) {
            printErr(requestId, e.getMessage(), "INVALID_ARGS", e);

        } catch (NotBoundException e) {
            printErr(requestId, "RMI service not bound: " + DEFAULT_BINDING, "NOT_BOUND", e);

        } catch (ConnectIOException e) {

            printErr(requestId, "RMI connection I/O error", "RMI_DOWN", e);

        } catch (RemoteException e) {

            String msg = "Remote error: " + safeMsg(e);

            Throwable cause = e.getCause();
            if (cause instanceof java.net.ConnectException) {
                msg = "RMI service unreachable (connection refused)";
            }

            printErr(requestId, msg, "REMOTE_ERROR", e);

        } catch (Exception e) {
            printErr(requestId, "Exception: " + safeMsg(e), "CLIENT_ERROR", e);
        }
    }


    private static void requireArgs(String[] args, int n, String usage) {
        if (args == null || args.length < n) throw new IllegalArgumentException(usage);
    }

    private static int parseIntStrict(String s, String field) {
        try { return Integer.parseInt(s); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid " + field + ": " + s); }
    }

    private static int parseIntSafe(String s, int def) {
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    private static double parseDoubleStrict(String s, String field) {
        try {
            double v = Double.parseDouble(s);
            if (!Double.isFinite(v)) throw new NumberFormatException("not finite");
            return v;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid " + field + ": " + s);
        }
    }

    private static String getEnvOrDefault(String key, String def) {
        String v = System.getenv(key);
        return (v == null || v.trim().isEmpty()) ? def : v.trim();
    }

    private static String nz(String s) { return s == null ? "" : s; }

    private static String safeMsg(Throwable t) {
        String m = (t == null) ? "" : t.getMessage();
        return (m == null || m.trim().isEmpty()) ? t.getClass().getSimpleName() : m.trim();
    }

    private static void printOk(String requestId, String message, String dataJsonOrNull) {
        if (dataJsonOrNull == null || dataJsonOrNull.trim().isEmpty()) dataJsonOrNull = "null";
        String out =
                "{"
                        + "\"success\":true,"
                        + "\"message\":\"" + escapeJson(nz(message)) + "\","
                        + "\"data\":" + dataJsonOrNull + ","
                        + "\"error\":null,"
                        + "\"error_code\":null,"
                        + "\"request_id\":\"" + escapeJson(requestId) + "\""
                        + "}";
        System.out.println(out);
    }

    private static void printErr(String requestId, String message, String errorCode, Exception e) {
        String details = (e == null) ? "" : (e.getClass().getSimpleName() + ": " + nz(e.getMessage()));
        String errorCodeJson = (errorCode == null || errorCode.trim().isEmpty())
                ? "null"
                : "\"" + escapeJson(errorCode.trim()) + "\"";

        String out =
                "{"
                        + "\"success\":false,"
                        + "\"message\":\"" + escapeJson(nz(message)) + "\","
                        + "\"data\":null,"
                        + "\"error\":{"
                        +   "\"details\":\"" + escapeJson(nz(details)) + "\""
                        + "},"
                        + "\"error_code\":" + errorCodeJson + ","
                        + "\"request_id\":\"" + escapeJson(requestId) + "\""
                        + "}";
        System.out.println(out);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"':  out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
