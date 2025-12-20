package ma.fsa.bank.client;

import ma.fsa.bank.common.dto.*;
import ma.fsa.bank.rmi.interfaces.BankService;
import ma.fsa.bank.common.dto.UserProfileDTO;
import ma.fsa.bank.common.dto.UserProfileUpdateDTO;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.List;

public class RmiClient {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 1099;
    private static final String DEFAULT_BINDING = "BankService";

    public static void main(String[] args) {
        if (args == null || args.length < 1) {
            printError("No command provided");
            return;
        }

        String command = args[0];

        try {

            String host = getEnvOrDefault("BANK_RMI_HOST", DEFAULT_HOST);
            int port = parseIntSafe(getEnvOrDefault("BANK_RMI_PORT", String.valueOf(DEFAULT_PORT)), DEFAULT_PORT);

            Registry registry = LocateRegistry.getRegistry(host, port);
            BankService service = (BankService) registry.lookup(DEFAULT_BINDING);

            switch (command) {

                case "withdraw": {
                    requireArgs(args, 3, "Usage: withdraw <accountNumber> <amount>");
                    String acc = args[1];
                    double amount = parseDoubleStrict(args[2], "amount");

                    boolean ok = service.withdraw(acc, amount);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }


                case "get_user_profile": {
                    requireArgs(args, 2, "Usage: get_user_profile <userId>");
                    int userId = parseIntStrict(args[1], "userId");

                    UserProfileDTO p = service.getUserProfile(userId);
                    if (p == null) {
                        System.out.println("{\"success\":false,\"error\":\"User not found\"}");
                        break;
                    }

                    String clientIdPart = (p.getClientId() == null) ? "null" : String.valueOf(p.getClientId());

                    String json = "{"
                            + "\"success\":true,"
                            + "\"profile\":{"
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
                            + "}"
                            + "}";

                    System.out.println(json);
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

                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }

                case "deposit": {
                    requireArgs(args, 3, "Usage: deposit <accountNumber> <amount>");
                    String acc = args[1];
                    double amount = parseDoubleStrict(args[2], "amount");

                    boolean ok = service.deposit(acc, amount);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }

                case "transfer": {
                    requireArgs(args, 4, "Usage: transfer <fromAccountNumber> <toAccountNumber> <amount>");
                    String fromAcc = args[1];
                    String toAcc = args[2];
                    double amount = parseDoubleStrict(args[3], "amount");

                    boolean ok = service.transfer(fromAcc, toAcc, amount);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }

                case "get_client_accounts": {
                    requireArgs(args, 2, "Usage: get_client_accounts <clientId>");
                    int clientId = parseIntStrict(args[1], "clientId");

                    List<AccountDTO> accounts = service.getClientAccounts(clientId);

                    StringBuilder sb = new StringBuilder(256);
                    sb.append("{\"success\":true,\"accounts\":[");
                    for (int i = 0; i < accounts.size(); i++) {
                        AccountDTO acc = accounts.get(i);
                        sb.append("{\"id\":")
                                .append(acc.getId())
                                .append(",\"number\":\"")
                                .append(escapeJson(acc.getAccountNumber()))
                                .append("\",\"balance\":")
                                .append(acc.getBalance())
                                .append("}");
                        if (i < accounts.size() - 1) sb.append(",");
                    }
                    sb.append("]}");
                    System.out.println(sb);
                    break;
                }

                case "get_balance": {
                    requireArgs(args, 2, "Usage: get_balance <accountNumber>");
                    String accountNumber = args[1];
                    double balance = service.getBalance(accountNumber);

                    System.out.println("{\"success\":true," +
                            "\"account\":\"" + escapeJson(accountNumber) + "\"," +
                            "\"balance\":" + balance + "}");
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

                    System.out.println("{\"success\":" + resp.isSuccess() +
                            ",\"message\":\"" + escapeJson(resp.getMessage()) + "\"}");
                    break;
                }

                case "admin_reset_password": {
                    requireArgs(args, 4, "Usage: admin_reset_password <actorUserId> <targetUserId> <newPassword>");
                    int actorId = parseIntStrict(args[1], "actorUserId");
                    int targetId = parseIntStrict(args[2], "targetUserId");
                    String newPass = args[3];

                    boolean ok = service.adminResetPassword(actorId, targetId, newPass);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }

                case "login": {
                    requireArgs(args, 3, "Usage: login <username> <password>");
                    String username = args[1];
                    String password = args[2];

                    UserDTO user = service.authenticate(username, password);
                    if (user == null) {
                        System.out.println("{\"success\":false,\"error\":\"Invalid credentials\"}");
                    } else {
                        String clientIdPart = (user.getClientId() == null) ? "null" : String.valueOf(user.getClientId());

                        System.out.println("{\"success\":true," +
                                "\"id\":" + user.getId() + "," +
                                "\"client_id\":" + clientIdPart + "," +
                                "\"username\":\"" + escapeJson(user.getUsername()) + "\"," +
                                "\"role\":\"" + escapeJson(user.getRole()) + "\"," +
                                "\"active\":" + user.isActive() + "," +
                                "\"is_super_admin\":" + user.isSuperAdmin() +
                                "}");

                    }
                    break;
                }

                case "get_transactions": {
                    requireArgs(args, 2, "Usage: get_transactions <accountNumber>");
                    String acc = args[1];

                    List<TransactionDTO> txs = service.getTransactions(acc);

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"success\":true,\"account\":\"")
                            .append(escapeJson(acc))
                            .append("\",\"transactions\":[");
                    for (int i = 0; i < txs.size(); i++) {
                        TransactionDTO t = txs.get(i);
                        sb.append("{\"id\":").append(t.getId())
                                .append(",\"type\":\"").append(escapeJson(t.getType())).append("\"")
                                .append(",\"amount\":").append(t.getAmount())
                                .append(",\"balance_after\":").append(t.getBalanceAfter())
                                .append(",\"date\":").append(t.getDate() != null ? t.getDate().getTime() : 0)
                                .append("}");
                        if (i < txs.size() - 1) sb.append(",");
                    }
                    sb.append("]}");
                    System.out.println(sb);
                    break;
                }



                case "create_account": {
                    requireArgs(args, 5, "Usage: create_account <clientId> <branchId> <type> <currency>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    int branchId = parseIntStrict(args[2], "branchId");
                    String type = args[3];
                    String currency = args[4];

                    AccountDTO acc = service.createAccount(clientId, branchId, type, currency);

                    System.out.println("{\"success\":true," +
                            "\"id\":" + acc.getId() + "," +
                            "\"number\":\"" + escapeJson(acc.getAccountNumber()) + "\"," +
                            "\"balance\":" + acc.getBalance() + "}");
                    break;
                }

                case "close_account": {
                    requireArgs(args, 2, "Usage: close_account <accountNumber>");
                    String accountNumber = args[1];
                    boolean ok = service.closeAccount(accountNumber);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }



                case "list_users": {
                    List<UserDTO> users = service.listUsers();

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"success\":true,\"users\":[");
                    for (int i = 0; i < users.size(); i++) {
                        UserDTO u = users.get(i);
                        String clientIdPart = (u.getClientId() == null) ? "null" : String.valueOf(u.getClientId());

                        sb.append("{\"id\":").append(u.getId())
                                .append(",\"client_id\":").append(clientIdPart)
                                .append(",\"username\":\"").append(escapeJson(u.getUsername())).append("\"")
                                .append(",\"role\":\"").append(escapeJson(u.getRole())).append("\"")
                                .append(",\"active\":").append(u.isActive())
                                .append("}");
                        if (i < users.size() - 1) sb.append(",");
                    }
                    sb.append("]}");
                    System.out.println(sb);
                    break;
                }

                case "create_admin": {
                    requireArgs(args, 3, "Usage: create_admin <username> <password>");
                    String username = args[1];
                    String password = args[2];

                    UserDTO admin = service.createAdminUser(username, password);
                    String clientIdPart = (admin.getClientId() == null) ? "null" : String.valueOf(admin.getClientId());

                    System.out.println("{\"success\":true," +
                            "\"id\":" + admin.getId() + "," +
                            "\"client_id\":" + clientIdPart + "," +
                            "\"username\":\"" + escapeJson(admin.getUsername()) + "\"," +
                            "\"role\":\"" + escapeJson(admin.getRole()) + "\"," +
                            "\"active\":" + admin.isActive() + "}");
                    break;
                }

                case "admin_stats": {
                    AdminGlobalStatsDTO s = service.getAdminGlobalStats();

                    String json = "{"
                            + "\"success\":true,"
                            + "\"stats\":{"
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
                            + "}"
                            + "}";

                    System.out.println(json);
                    break;
                }

                case "set_user_active": {
                    requireArgs(args, 3, "Usage: set_user_active <userId> <true|false>");
                    int userId = parseIntStrict(args[1], "userId");
                    boolean active = Boolean.parseBoolean(args[2]);

                    boolean ok = service.setUserActive(userId, active);
                    System.out.println("{\"success\":" + ok + "}");
                    break;
                }

                case "get_all_transactions": {
                    List<TransactionDTO> list = service.getAllTransactions();

                    StringBuilder sb = new StringBuilder(1024);
                    sb.append("{\"success\":true,\"transactions\":[");
                    for (int i = 0; i < list.size(); i++) {
                        TransactionDTO t = list.get(i);
                        sb.append("{\"id\":").append(t.getId())
                                .append(",\"account\":\"").append(escapeJson(nz(t.getAccountNumber()))).append("\"")
                                .append(",\"type\":\"").append(escapeJson(t.getType())).append("\"")
                                .append(",\"amount\":").append(t.getAmount())
                                .append(",\"balance_after\":").append(t.getBalanceAfter())
                                .append(",\"date\":").append(t.getDate() != null ? t.getDate().getTime() : 0)
                                .append(",\"branch_name\":\"").append(escapeJson(nz(t.getBranchName()))).append("\"")
                                .append("}");
                        if (i < list.size() - 1) sb.append(",");
                    }
                    sb.append("]}");
                    System.out.println(sb);
                    break;
                }

                case "list_branches": {
                    List<BranchDTO> branches = service.listBranches();

                    StringBuilder sb = new StringBuilder(512);
                    sb.append("{\"success\":true,\"branches\":[");
                    for (int i = 0; i < branches.size(); i++) {
                        BranchDTO b = branches.get(i);
                        sb.append("{\"id\":").append(b.getId())
                                .append(",\"code\":\"").append(escapeJson(b.getCode())).append("\"")
                                .append(",\"name\":\"").append(escapeJson(b.getName())).append("\"")
                                .append(",\"city\":\"").append(escapeJson(b.getCity())).append("\"")
                                .append("}");
                        if (i < branches.size() - 1) sb.append(",");
                    }
                    sb.append("]}");
                    System.out.println(sb);
                    break;
                }



                case "get_client_type": {
                    requireArgs(args, 2, "Usage: get_client_type <clientId>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    String type = service.getClientType(clientId);
                    System.out.println("{\"success\":true,\"client_id\":" + clientId + ",\"client_type\":\"" + escapeJson(type) + "\"}");
                    break;
                }

                case "set_client_type": {
                    requireArgs(args, 3, "Usage: set_client_type <clientId> <STANDARD|PREMIUM|VIP|ENTREPRISE|ETUDIANT>");
                    int clientId = parseIntStrict(args[1], "clientId");
                    String type = args[2];
                    boolean ok = service.setClientType(clientId, type);
                    System.out.println("{\"success\":" + ok + ",\"client_id\":" + clientId + ",\"client_type\":\"" + escapeJson(type) + "\"}");
                    break;
                }

                case "get_limits": {
                    requireArgs(args, 2, "Usage: get_limits <accountNumber>");
                    String acc = args[1];
                    AccountLimitsDTO lim = service.getAccountLimits(acc);

                    System.out.println("{\"success\":true," +
                            "\"account\":\"" + escapeJson(lim.getAccountNumber()) + "\"," +
                            "\"client_type\":\"" + escapeJson(lim.getClientType()) + "\"," +
                            "\"daily_transfer_limit\":" + lim.getDailyTransferLimit() + "," +
                            "\"daily_debit_limit\":" + lim.getDailyDebitLimit() +
                            "}");
                    break;
                }

                default:
                    printError("Unknown command: " + command);
            }

        } catch (IllegalArgumentException e) {
            printError(e.getMessage());
        } catch (Exception e) {
            printError("Exception: " + e.getMessage());
        }
    }

    private static void requireArgs(String[] args, int n, String usage) {
        if (args == null || args.length < n) throw new IllegalArgumentException(usage);
    }

    private static int parseIntStrict(String s, String field) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid " + field + ": " + s);
        }
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

    private static void printError(String message) {
        System.out.println("{\"success\":false,\"error\":\"" + escapeJson(message) + "\"}");
    }

    // JSON escape plus robuste
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
