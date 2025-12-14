package ma.fsa.bank.server;

import ma.fsa.bank.common.dto.*;
import ma.fsa.bank.rmi.interfaces.BankService;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class BankServiceImpl extends UnicastRemoteObject implements BankService {

    // ===== Limites de BASE (profil STANDARD) =====
    private static final double BASE_DAILY_TRANSFER_LIMIT = 20000.0; // TRANSFER debit
    private static final double BASE_DAILY_DEBIT_LIMIT    = 5000.0;  // total DEBIT (withdraw+transfer)

    // Nombre max de comptes actifs par client
    private static final int MAX_ACTIVE_ACCOUNTS_PER_CLIENT = 3;

    public BankServiceImpl() throws RemoteException {
        super();
    }

    // =========================================================
    //  PROFILS CLIENTS + LIMITES DYNAMIQUES
    // =========================================================

    private double coeffByClientType(String t) {
        if (t == null) return 1.0;
        switch (t.toUpperCase()) {
            case "PREMIUM":    return 2.0;
            case "VIP":        return 5.0;
            case "ENTREPRISE": return 10.0;
            case "ETUDIANT":   return 0.5;
            default:           return 1.0; // STANDARD
        }
    }

    private String normalizeClientType(String t) {
        if (t == null) return "STANDARD";
        String up = t.toUpperCase();
        if (up.equals("STANDARD") || up.equals("PREMIUM") || up.equals("VIP")
                || up.equals("ENTREPRISE") || up.equals("ETUDIANT")) {
            return up;
        }
        return "STANDARD";
    }

    private String getClientTypeByAccountId(Connection conn, int accountId) throws SQLException {
        String sql =
                "SELECT c.client_type " +
                        "FROM account a JOIN client c ON a.client_id = c.id " +
                        "WHERE a.id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return normalizeClientType(rs.getString("client_type"));
            }
        }
        return "STANDARD";
    }

    private int getClientIdByAccountId(Connection conn, int accountId) throws SQLException {
        String sql = "SELECT client_id FROM account WHERE id=?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt("client_id");
            }
        }
        throw new SQLException("client_id introuvable pour account_id=" + accountId);
    }

    /**
     * Migration auto : STANDARD/PREMIUM/VIP seulement.
     * ENTREPRISE et ETUDIANT ne sont jamais changés automatiquement.
     */
    private void autoMigrateClientType(Connection conn, int clientId) throws SQLException {
        String current = "STANDARD";
        try (PreparedStatement ps = conn.prepareStatement("SELECT client_type FROM client WHERE id=?")) {
            ps.setInt(1, clientId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) current = normalizeClientType(rs.getString("client_type"));
            }
        }

        if (current.equals("ENTREPRISE") || current.equals("ETUDIANT")) return;

        double avgBal = 0.0;
        String sqlAvg = "SELECT COALESCE(AVG(balance),0) AS avg_bal FROM account WHERE client_id=? AND status='ACTIVE'";
        try (PreparedStatement ps = conn.prepareStatement(sqlAvg)) {
            ps.setInt(1, clientId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) avgBal = rs.getDouble("avg_bal");
            }
        }

        String target;
        if (avgBal > 500_000) target = "VIP";
        else if (avgBal > 100_000) target = "PREMIUM";
        else target = "STANDARD";

        if (!target.equals(current)) {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE client SET client_type=? WHERE id=?")) {
                ps.setString(1, target);
                ps.setInt(2, clientId);
                ps.executeUpdate();
            }
        }
    }

    // ---------- Utilitaires internes ----------

    private void requirePositiveFiniteAmount(double amount) throws RemoteException {
        if (!(amount > 0.0) || !Double.isFinite(amount)) {
            throw new RemoteException("Montant invalide");
        }
    }

    private double getTodayDebitSum(Connection conn, int accountId, String typeCode) throws SQLException {
        String sql =
                "SELECT COALESCE(SUM(amount), 0) AS total " +
                        "FROM `transaction` " +
                        "WHERE account_id = ? " +
                        "  AND type_code = ? " +
                        "  AND direction = 'DEBIT' " +
                        "  AND DATE(created_at) = CURDATE()";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            ps.setString(2, typeCode);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getDouble("total");
                return 0.0;
            }
        }
    }

    private double getTodayTotalDebits(Connection conn, int accountId) throws SQLException {
        String sql =
                "SELECT COALESCE(SUM(amount), 0) AS total " +
                        "FROM `transaction` " +
                        "WHERE account_id = ? " +
                        "  AND direction = 'DEBIT' " +
                        "  AND DATE(created_at) = CURDATE()";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getDouble("total");
                return 0.0;
            }
        }
    }

    private int countActiveAccountsForClient(Connection conn, int clientId) throws SQLException {
        String sql = "SELECT COUNT(*) AS cnt FROM account WHERE client_id = ? AND status = 'ACTIVE'";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, clientId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return rs.getInt("cnt");
                return 0;
            }
        }
    }

    /**
     * Lecture “FOR UPDATE” pour éviter les incohérences en concurrence (2 retraits en même temps).
     */
    private AccountDTO findAccountByNumberForUpdate(Connection conn, String accountNumber) throws SQLException {
        String sql =
                "SELECT id, account_number, balance " +
                        "FROM account " +
                        "WHERE account_number = ? AND status = 'ACTIVE' " +
                        "FOR UPDATE";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new AccountDTO(
                            rs.getInt("id"),
                            rs.getString("account_number"),
                            rs.getDouble("balance")
                    );
                }
                return null;
            }
        }
    }

    private AccountDTO findAccountByNumber(Connection conn, String accountNumber) throws SQLException {
        String sql =
                "SELECT id, account_number, balance " +
                        "FROM account " +
                        "WHERE account_number = ? AND status = 'ACTIVE'";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, accountNumber);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new AccountDTO(
                            rs.getInt("id"),
                            rs.getString("account_number"),
                            rs.getDouble("balance")
                    );
                }
                return null;
            }
        }
    }

    private String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private void insertTransaction(
            Connection conn,
            int accountId,
            Integer counterpartAccountId,
            String typeCode,
            String direction,
            double amount,
            double balanceAfter,
            String description
    ) throws SQLException {

        String sql = "INSERT INTO `transaction` " +
                "(account_id, counterpart_account_id, type_code, direction, amount, balance_after, status, description) " +
                "VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', ?)";

        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, accountId);
            if (counterpartAccountId != null) ps.setInt(2, counterpartAccountId);
            else ps.setNull(2, Types.INTEGER);

            ps.setString(3, typeCode);
            ps.setString(4, direction);
            ps.setDouble(5, amount);
            ps.setDouble(6, balanceAfter);
            ps.setString(7, description);
            ps.executeUpdate();
        }
    }

    private String generateNextAccountNumber(Connection conn, int clientId, int branchId) throws SQLException {
        String sql = "SELECT COUNT(*) AS cnt FROM account WHERE client_id = ? AND branch_id = ?";
        int count = 0;
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, clientId);
            ps.setInt(2, branchId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) count = rs.getInt("cnt");
            }
        }
        int index = count + 1;
        String suffix = String.format("%03d", index);

        return "ACC-" + String.format("%03d", branchId) + "-" +
                String.format("%04d", clientId) + "-" + suffix;
    }

    // =============================
    // Admin : users
    // =============================

    @Override
    public List<UserDTO> listUsers() throws RemoteException {
        List<UserDTO> result = new ArrayList<>();
        String sql = "SELECT id, client_id, username, role, is_active, is_super_admin, created_by FROM `user`";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                int id = rs.getInt("id");
                Object clientObj = rs.getObject("client_id");
                Integer clientId = (clientObj != null) ? rs.getInt("client_id") : null;

                String username = rs.getString("username");
                String role = rs.getString("role");
                boolean active = rs.getBoolean("is_active");

                boolean isSuperAdmin = rs.getBoolean("is_super_admin");
                Object createdByObj = rs.getObject("created_by");
                Integer createdBy = (createdByObj != null) ? rs.getInt("created_by") : null;

                result.add(new UserDTO(id, clientId, username, role, active, isSuperAdmin, createdBy));
            }
            return result;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans listUsers", e);
        }
    }


    @Override
    public UserDTO createAdminUser(String username, String plainPassword) throws RemoteException {
        if (username == null || username.trim().isEmpty()) throw new RemoteException("Username invalide");
        if (plainPassword == null || plainPassword.isEmpty()) throw new RemoteException("Password invalide");

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                String sqlCheck = "SELECT COUNT(*) FROM `user` WHERE username = ?";
                try (PreparedStatement ps = conn.prepareStatement(sqlCheck)) {
                    ps.setString(1, username);
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        if (rs.getInt(1) > 0) {
                            conn.rollback();
                            throw new RemoteException("Nom d'utilisateur déjà utilisé");
                        }
                    }
                }

                String passwordHash = hashPassword(plainPassword);

                String sqlInsert =
                        "INSERT INTO `user` (client_id, username, password_hash, role, is_active) " +
                                "VALUES (NULL, ?, ?, 'ADMIN', 1)";

                int userId;
                try (PreparedStatement ps = conn.prepareStatement(sqlInsert, Statement.RETURN_GENERATED_KEYS)) {
                    ps.setString(1, username);
                    ps.setString(2, passwordHash);
                    ps.executeUpdate();

                    try (ResultSet rs = ps.getGeneratedKeys()) {
                        if (!rs.next()) {
                            conn.rollback();
                            throw new RemoteException("Echec création admin");
                        }
                        userId = rs.getInt(1);
                    }
                }

                conn.commit();
                return new UserDTO(userId, null, username, "ADMIN", true);

            } catch (RemoteException e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw e;
            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans createAdminUser", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans createAdminUser", e);
        }
    }

    @Override
    public boolean setUserActive(int userId, boolean active) throws RemoteException {
        String sql = "UPDATE `user` SET is_active = ? WHERE id = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setBoolean(1, active);
            ps.setInt(2, userId);
            return ps.executeUpdate() > 0;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans setUserActive", e);
        }
    }

    // =============================
    // Inscription
    // =============================

    @Override
    public RegisterResponse registerUser(RegisterRequest req) throws RemoteException {
        if (req == null) return new RegisterResponse(false, "Requête invalide");
        if (req.getUsername() == null || req.getUsername().trim().isEmpty()) return new RegisterResponse(false, "Username invalide");
        if (req.getPlainPassword() == null || req.getPlainPassword().isEmpty()) return new RegisterResponse(false, "Password invalide");

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                String sqlUser = "SELECT COUNT(*) FROM `user` WHERE username = ?";
                try (PreparedStatement checkUser = conn.prepareStatement(sqlUser)) {
                    checkUser.setString(1, req.getUsername());
                    try (ResultSet rs = checkUser.executeQuery()) {
                        rs.next();
                        if (rs.getInt(1) > 0) {
                            conn.rollback();
                            return new RegisterResponse(false, "Nom d'utilisateur deja utilise");
                        }
                    }
                }

                Integer branchId = null;
                String sqlBranch = "SELECT id FROM branch ORDER BY id LIMIT 1";
                try (PreparedStatement stmt = conn.prepareStatement(sqlBranch);
                     ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) branchId = rs.getInt("id");
                }
                if (branchId == null) {
                    conn.rollback();
                    return new RegisterResponse(false, "Aucune agence configuree dans la base.");
                }

                String generatedCin = "TMP-" + System.currentTimeMillis();

                String insertClientSql =
                        "INSERT INTO client (branch_id, first_name, last_name, cin, email, phone, address, client_type) " +
                                "VALUES (?, ?, ?, ?, NULL, NULL, NULL, 'STANDARD')";

                int clientId;
                try (PreparedStatement insertClient =
                             conn.prepareStatement(insertClientSql, Statement.RETURN_GENERATED_KEYS)) {

                    insertClient.setInt(1, branchId);
                    insertClient.setString(2, req.getUsername());
                    insertClient.setString(3, "Client");
                    insertClient.setString(4, generatedCin);
                    insertClient.executeUpdate();

                    try (ResultSet genKeys = insertClient.getGeneratedKeys()) {
                        if (!genKeys.next()) {
                            conn.rollback();
                            return new RegisterResponse(false, "Echec lors de la creation du client");
                        }
                        clientId = genKeys.getInt(1);
                    }
                }

                String passwordHash = hashPassword(req.getPlainPassword());

                String insertUserSql =
                        "INSERT INTO `user` (client_id, username, password_hash, role, is_active) " +
                                "VALUES (?, ?, ?, 'CLIENT', 1)";

                try (PreparedStatement insertUser = conn.prepareStatement(insertUserSql)) {
                    insertUser.setInt(1, clientId);
                    insertUser.setString(2, req.getUsername());
                    insertUser.setString(3, passwordHash);
                    insertUser.executeUpdate();
                }

                String accountNumber = generateNextAccountNumber(conn, clientId, branchId);

                String insertAccountSql =
                        "INSERT INTO account (client_id, branch_id, account_number, type, currency, balance, status) " +
                                "VALUES (?, ?, ?, 'CHECKING', 'MAD', 0.00, 'ACTIVE')";

                try (PreparedStatement insertAccount = conn.prepareStatement(insertAccountSql)) {
                    insertAccount.setInt(1, clientId);
                    insertAccount.setInt(2, branchId);
                    insertAccount.setString(3, accountNumber);
                    insertAccount.executeUpdate();
                }

                conn.commit();
                return new RegisterResponse(true, "Inscription reussie");

            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                return new RegisterResponse(false, "Erreur interne serveur");
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans registerUser", e);
        }
    }

    // =============================
    // Authentification
    // =============================

    @Override
    public UserDTO authenticate(String username, String password) throws RemoteException {
        String sql = "SELECT id, client_id, username, password_hash, role, is_active, is_super_admin, created_by " +
                "FROM `user` WHERE username = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;

                boolean isActive = rs.getBoolean("is_active");
                if (!isActive) return null;

                String storedHash = rs.getString("password_hash");
                String givenHash = hashPassword(password);
                if (!storedHash.equals(givenHash)) return null;

                int id = rs.getInt("id");
                Integer clientId = rs.getObject("client_id") != null ? rs.getInt("client_id") : null;
                String role = rs.getString("role");

                boolean isSuperAdmin = rs.getBoolean("is_super_admin");
                Object createdByObj = rs.getObject("created_by");
                Integer createdBy = (createdByObj != null) ? rs.getInt("created_by") : null;

                return new UserDTO(id, clientId, username, role, true, isSuperAdmin, createdBy);
            }

        } catch (Exception e) {
            throw new RemoteException("Erreur lors de l'authentification", e);
        }
    }


    // =============================
    // Opérations classiques
    // =============================

    @Override
    public double getBalance(String accountNumber) throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {
            AccountDTO account = findAccountByNumber(conn, accountNumber);
            if (account == null) throw new RemoteException("Compte introuvable : " + accountNumber);
            return account.getBalance();
        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getBalance", e);
        }
    }

    @Override
    public boolean deposit(String accountNumber, double amount) throws RemoteException {
        requirePositiveFiniteAmount(amount);

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                AccountDTO account = findAccountByNumberForUpdate(conn, accountNumber);
                if (account == null) { conn.rollback(); return false; }

                double newBalance = account.getBalance() + amount;

                try (PreparedStatement ps = conn.prepareStatement("UPDATE account SET balance = ? WHERE id = ?")) {
                    ps.setDouble(1, newBalance);
                    ps.setInt(2, account.getId());
                    ps.executeUpdate();
                }

                insertTransaction(conn, account.getId(), null, "DEPOSIT", "CREDIT", amount, newBalance, "Depot via RMI");

                int clientId = getClientIdByAccountId(conn, account.getId());
                autoMigrateClientType(conn, clientId);

                conn.commit();
                return true;

            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans deposit", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans deposit", e);
        }
    }

    @Override
    public boolean withdraw(String accountNumber, double amount) throws RemoteException {
        requirePositiveFiniteAmount(amount);

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                AccountDTO account = findAccountByNumberForUpdate(conn, accountNumber);
                if (account == null) { conn.rollback(); return false; }

                String type = getClientTypeByAccountId(conn, account.getId());
                double coeff = coeffByClientType(type);

                double dynamicDailyDebitLimit = BASE_DAILY_DEBIT_LIMIT * coeff;

                double alreadyToday = getTodayTotalDebits(conn, account.getId());
                if (alreadyToday + amount > dynamicDailyDebitLimit) {
                    conn.rollback();
                    return false;
                }

                if (account.getBalance() < amount) {
                    conn.rollback();
                    return false;
                }

                double newBalance = account.getBalance() - amount;

                try (PreparedStatement ps = conn.prepareStatement("UPDATE account SET balance = ? WHERE id = ?")) {
                    ps.setDouble(1, newBalance);
                    ps.setInt(2, account.getId());
                    ps.executeUpdate();
                }

                insertTransaction(conn, account.getId(), null, "WITHDRAWAL", "DEBIT", amount, newBalance, "Retrait via RMI");

                int clientId = getClientIdByAccountId(conn, account.getId());
                autoMigrateClientType(conn, clientId);

                conn.commit();
                return true;

            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans withdraw", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans withdraw", e);
        }
    }

    @Override
    public boolean transfer(String fromAccount, String toAccount, double amount) throws RemoteException {
        requirePositiveFiniteAmount(amount);
        if (fromAccount == null || toAccount == null) return false;
        if (fromAccount.equals(toAccount)) return false;

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // Astuce anti-deadlock: verrouiller dans un ordre déterministe
                String a = fromAccount.compareTo(toAccount) <= 0 ? fromAccount : toAccount;
                String b = fromAccount.compareTo(toAccount) <= 0 ? toAccount : fromAccount;

                AccountDTO first = findAccountByNumberForUpdate(conn, a);
                AccountDTO second = findAccountByNumberForUpdate(conn, b);

                if (first == null || second == null) { conn.rollback(); return false; }

                AccountDTO source = fromAccount.equals(a) ? first : second;
                AccountDTO target = toAccount.equals(a) ? first : second;

                if (source.getBalance() < amount) { conn.rollback(); return false; }

                String clientType = getClientTypeByAccountId(conn, source.getId());
                double coeff = coeffByClientType(clientType);

                double dynamicTransferLimit = BASE_DAILY_TRANSFER_LIMIT * coeff;
                double dynamicDebitLimit    = BASE_DAILY_DEBIT_LIMIT * coeff;

                double alreadyTransferToday = getTodayDebitSum(conn, source.getId(), "TRANSFER");
                if (alreadyTransferToday + amount > dynamicTransferLimit) { conn.rollback(); return false; }

                double alreadyDebitsToday = getTodayTotalDebits(conn, source.getId());
                if (alreadyDebitsToday + amount > dynamicDebitLimit) { conn.rollback(); return false; }

                double newSourceBalance = source.getBalance() - amount;
                double newTargetBalance = target.getBalance() + amount;

                try (PreparedStatement ps = conn.prepareStatement("UPDATE account SET balance = ? WHERE id = ?")) {
                    ps.setDouble(1, newSourceBalance);
                    ps.setInt(2, source.getId());
                    ps.executeUpdate();
                }

                try (PreparedStatement ps = conn.prepareStatement("UPDATE account SET balance = ? WHERE id = ?")) {
                    ps.setDouble(1, newTargetBalance);
                    ps.setInt(2, target.getId());
                    ps.executeUpdate();
                }

                insertTransaction(conn, source.getId(), target.getId(), "TRANSFER", "DEBIT", amount, newSourceBalance, "Virement vers " + toAccount);
                insertTransaction(conn, target.getId(), source.getId(), "TRANSFER", "CREDIT", amount, newTargetBalance, "Virement depuis " + fromAccount);

                int clientId = getClientIdByAccountId(conn, source.getId());
                autoMigrateClientType(conn, clientId);

                conn.commit();
                return true;

            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans transfer", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans transfer", e);
        }
    }

    @Override
    public AccountDTO getAccount(String accountNumber) throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {
            AccountDTO account = findAccountByNumber(conn, accountNumber);
            if (account == null) throw new RemoteException("Compte introuvable : " + accountNumber);
            return account;
        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getAccount", e);
        }
    }

    @Override
    public List<TransactionDTO> getTransactions(String accountNumber) throws RemoteException {
        List<TransactionDTO> result = new ArrayList<>();

        try (Connection conn = DBConnection.getConnection()) {

            AccountDTO account = findAccountByNumber(conn, accountNumber);
            if (account == null) throw new RemoteException("Compte introuvable : " + accountNumber);

            String sql =
                    "SELECT id, type_code, amount, balance_after, created_at " +
                            "FROM `transaction` WHERE account_id = ? ORDER BY created_at DESC";

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, account.getId());

                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        long id = rs.getLong("id");
                        String type = rs.getString("type_code");
                        double amount = rs.getDouble("amount");
                        double balanceAfter = rs.getDouble("balance_after");
                        Timestamp ts = rs.getTimestamp("created_at");

                        result.add(new TransactionDTO(
                                id, type, amount, balanceAfter,
                                ts != null ? new java.util.Date(ts.getTime()) : null
                        ));
                    }
                }
            }
            return result;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getTransactions", e);
        }
    }

    @Override
    public List<AccountDTO> getClientAccounts(int clientId) throws RemoteException {
        List<AccountDTO> result = new ArrayList<>();

        try (Connection conn = DBConnection.getConnection()) {
            String sql =
                    "SELECT id, account_number, balance " +
                            "FROM account WHERE client_id = ? AND status = 'ACTIVE'";

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, clientId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        result.add(new AccountDTO(
                                rs.getInt("id"),
                                rs.getString("account_number"),
                                rs.getDouble("balance")
                        ));
                    }
                }
            }
            return result;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getClientAccounts", e);
        }
    }

    @Override
    public boolean closeAccount(String accountNumber) throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "UPDATE account SET status = 'CLOSED' WHERE account_number = ? AND status='ACTIVE'";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, accountNumber);
                return ps.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans closeAccount", e);
        }
    }

    // =============================
    // Stats Admin
    // =============================

    @Override
    public AdminGlobalStatsDTO getAdminGlobalStats() throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {

            int totalUsers = 0;
            int totalClients = 0;
            int totalAdmins = 0;

            String sqlUsers =
                    "SELECT role, COUNT(*) AS cnt " +
                            "FROM `user` " +
                            "GROUP BY role";

            try (PreparedStatement ps = conn.prepareStatement(sqlUsers);
                 ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String role = rs.getString("role");
                    int cnt = rs.getInt("cnt");
                    totalUsers += cnt;

                    if ("CLIENT".equalsIgnoreCase(role)) totalClients += cnt;
                    else if ("ADMIN".equalsIgnoreCase(role)) totalAdmins += cnt;
                }
            }

            int totalBranches = 0;
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) AS c FROM branch");
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) totalBranches = rs.getInt("c");
            }

            int activeAccounts = 0;
            int closedAccounts = 0;

            String sqlAccounts =
                    "SELECT status, COUNT(*) AS cnt " +
                            "FROM account " +
                            "GROUP BY status";

            try (PreparedStatement ps = conn.prepareStatement(sqlAccounts);
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String status = rs.getString("status");
                    int cnt = rs.getInt("cnt");
                    if ("ACTIVE".equalsIgnoreCase(status)) activeAccounts += cnt;
                    else if ("CLOSED".equalsIgnoreCase(status)) closedAccounts += cnt;
                }
            }

            long totalTransactions = 0;

            long totalDepositsCount = 0;
            double totalDepositsAmount = 0.0;

            long totalWithdrawalsCount = 0;
            double totalWithdrawalsAmount = 0.0;

            long totalTransfersCount = 0;
            double totalTransfersAmount = 0.0;

            String sqlTx =
                    "SELECT type_code, COUNT(*) AS cnt, COALESCE(SUM(amount), 0) AS total " +
                            "FROM `transaction` " +
                            "GROUP BY type_code";

            try (PreparedStatement ps = conn.prepareStatement(sqlTx);
                 ResultSet rs = ps.executeQuery()) {

                while (rs.next()) {
                    String type = rs.getString("type_code");
                    long cnt = rs.getLong("cnt");
                    double total = rs.getDouble("total");
                    totalTransactions += cnt;

                    if ("DEPOSIT".equalsIgnoreCase(type)) {
                        totalDepositsCount = cnt;
                        totalDepositsAmount = total;
                    } else if ("WITHDRAWAL".equalsIgnoreCase(type)) {
                        totalWithdrawalsCount = cnt;
                        totalWithdrawalsAmount = total;
                    } else if ("TRANSFER".equalsIgnoreCase(type)) {
                        totalTransfersCount = cnt;
                        totalTransfersAmount = total;
                    }
                }
            }

            return new AdminGlobalStatsDTO(
                    totalUsers,
                    totalClients,
                    totalAdmins,
                    totalBranches,
                    activeAccounts,
                    closedAccounts,
                    totalTransactions,
                    totalDepositsCount,
                    totalDepositsAmount,
                    totalWithdrawalsCount,
                    totalWithdrawalsAmount,
                    totalTransfersCount,
                    totalTransfersAmount
            );

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getAdminGlobalStats", e);
        }
    }

    @Override
    public List<TransactionDTO> getAllTransactions() throws RemoteException {
        List<TransactionDTO> result = new ArrayList<>();

        String sql =
                "SELECT t.id, t.type_code, t.amount, t.balance_after, t.created_at, " +
                        "       a.account_number, " +
                        "       b.name AS branch_name " +
                        "FROM `transaction` t " +
                        "JOIN account a ON t.account_id = a.id " +
                        "JOIN branch b ON a.branch_id = b.id " +
                        "ORDER BY t.created_at DESC";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                long id = rs.getLong("id");
                String type = rs.getString("type_code");
                double amount = rs.getDouble("amount");
                double balanceAfter = rs.getDouble("balance_after");
                Timestamp ts = rs.getTimestamp("created_at");
                String accNum = rs.getString("account_number");
                String branchName = rs.getString("branch_name");

                result.add(new TransactionDTO(
                        id, type, amount, balanceAfter,
                        ts != null ? new java.util.Date(ts.getTime()) : null,
                        accNum, branchName
                ));
            }
            return result;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getAllTransactions", e);
        }
    }

    @Override
    public List<BranchDTO> listBranches() throws RemoteException {
        List<BranchDTO> result = new ArrayList<>();
        String sql = "SELECT id, code, name, city FROM branch";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                result.add(new BranchDTO(
                        rs.getInt("id"),
                        rs.getString("code"),
                        rs.getString("name"),
                        rs.getString("city")
                ));
            }
            return result;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans listBranches", e);
        }
    }

    @Override
    public AccountDTO createAccount(int clientId, int branchId, String type, String currency) throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM branch WHERE id = ?")) {
                    ps.setInt(1, branchId);
                    try (ResultSet rs = ps.executeQuery()) {
                        rs.next();
                        if (rs.getInt(1) == 0) {
                            conn.rollback();
                            throw new RemoteException("Agence introuvable: " + branchId);
                        }
                    }
                }

                int activeCount = countActiveAccountsForClient(conn, clientId);
                if (activeCount >= MAX_ACTIVE_ACCOUNTS_PER_CLIENT) {
                    conn.rollback();
                    throw new RemoteException("Limite de comptes actifs atteinte pour ce client.");
                }

                String t = (type == null) ? "CHECKING" : type.toUpperCase();
                if (!t.equals("CHECKING") && !t.equals("SAVINGS")) t = "CHECKING";

                String cur = (currency == null) ? "MAD" : currency.toUpperCase();
                if (!cur.equals("MAD") && !cur.equals("EUR") && !cur.equals("USD")) cur = "MAD";

                String accountNumber = generateNextAccountNumber(conn, clientId, branchId);

                String sql = "INSERT INTO account (client_id, branch_id, account_number, type, currency, balance, status) " +
                        "VALUES (?, ?, ?, ?, ?, 0.0, 'ACTIVE')";

                int accountId;
                try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                    ps.setInt(1, clientId);
                    ps.setInt(2, branchId);
                    ps.setString(3, accountNumber);
                    ps.setString(4, t);
                    ps.setString(5, cur);
                    ps.executeUpdate();

                    try (ResultSet rs = ps.getGeneratedKeys()) {
                        if (!rs.next()) {
                            conn.rollback();
                            throw new RemoteException("Echec creation compte");
                        }
                        accountId = rs.getInt(1);
                    }
                }

                conn.commit();
                return new AccountDTO(accountId, accountNumber, 0.0);

            } catch (RemoteException e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw e;
            } catch (SQLException e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur SQL dans createAccount", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }
        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans createAccount", e);
        }
    }

    // ==============================
    // Profils + plafonds dynamiques
    // ==============================

    @Override
    public String getClientType(int clientId) throws RemoteException {
        String sql = "SELECT client_type FROM client WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, clientId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) return normalizeClientType(rs.getString("client_type"));
            }
            return "STANDARD";

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getClientType", e);
        }
    }

    @Override
    public boolean setClientType(int clientId, String clientType) throws RemoteException {
        String normalized = normalizeClientType(clientType);

        String sql = "UPDATE client SET client_type = ? WHERE id = ?";
        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, normalized);
            ps.setInt(2, clientId);
            return ps.executeUpdate() > 0;

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans setClientType", e);
        }
    }

    @Override
    public AccountLimitsDTO getAccountLimits(String accountNumber) throws RemoteException {
        try (Connection conn = DBConnection.getConnection()) {

            AccountDTO acc = findAccountByNumber(conn, accountNumber);
            if (acc == null) throw new RemoteException("Compte introuvable : " + accountNumber);

            String clientType = getClientTypeByAccountId(conn, acc.getId());
            double coeff = coeffByClientType(clientType);

            double dailyTransfer = BASE_DAILY_TRANSFER_LIMIT * coeff;
            double dailyDebit = BASE_DAILY_DEBIT_LIMIT * coeff;

            return new AccountLimitsDTO(accountNumber, clientType, dailyTransfer, dailyDebit);

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getAccountLimits", e);
        }
    }
    // ==============================
    // Mon compte (profil user)
    // ==============================

    private String trimOrNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private boolean isValidUsername(String u) {
        if (u == null) return false;
        // même règle que ton form Django (3-50 lettres/chiffres/._-)
        return u.matches("^[a-zA-Z0-9_.-]{3,50}$");
    }

    @Override
    public UserProfileDTO getUserProfile(int userId) throws RemoteException {
        String sql =
                "SELECT u.id, u.client_id, u.username, u.role, u.is_active, " +
                        "       c.first_name, c.last_name, c.cin, c.email, c.phone, c.address, c.client_type " +
                        "FROM `user` u " +
                        "LEFT JOIN client c ON u.client_id = c.id " +
                        "WHERE u.id = ?";

        try (Connection conn = DBConnection.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);

            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;

                Integer clientId = (rs.getObject("client_id") != null) ? rs.getInt("client_id") : null;

                UserProfileDTO dto = new UserProfileDTO(
                        rs.getInt("id"),
                        clientId,
                        rs.getString("username"),
                        rs.getString("role"),
                        rs.getBoolean("is_active")
                );

                dto.setFirstName(rs.getString("first_name"));
                dto.setLastName(rs.getString("last_name"));
                dto.setCin(rs.getString("cin"));
                dto.setEmail(rs.getString("email"));
                dto.setPhone(rs.getString("phone"));
                dto.setAddress(rs.getString("address"));
                dto.setClientType(rs.getString("client_type"));

                return dto;
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans getUserProfile", e);
        }
    }

    @Override
    public boolean updateUserProfile(UserProfileUpdateDTO update) throws RemoteException {
        if (update == null) throw new RemoteException("Requête invalide");

        int userId = update.getUserId();
        String newUsername = trimOrNull(update.getUsername());

        if (!isValidUsername(newUsername)) {
            throw new RemoteException("Username invalide (3-50, lettres/chiffres/._-).");
        }

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // charger user + client_id
                Integer clientId = null;
                String currentUsername = null;

                try (PreparedStatement ps = conn.prepareStatement("SELECT client_id, username FROM `user` WHERE id=?")) {
                    ps.setInt(1, userId);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            conn.rollback();
                            throw new RemoteException("Utilisateur introuvable");
                        }
                        currentUsername = rs.getString("username");
                        clientId = (rs.getObject("client_id") != null) ? rs.getInt("client_id") : null;
                    }
                }

                // unicité username si changé
                if (currentUsername == null || !currentUsername.equals(newUsername)) {
                    try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM `user` WHERE username=? AND id<>?")) {
                        ps.setString(1, newUsername);
                        ps.setInt(2, userId);
                        try (ResultSet rs = ps.executeQuery()) {
                            rs.next();
                            if (rs.getInt(1) > 0) {
                                conn.rollback();
                                throw new RemoteException("Nom d'utilisateur déjà utilisé");
                            }
                        }
                    }

                    try (PreparedStatement ps = conn.prepareStatement("UPDATE `user` SET username=? WHERE id=?")) {
                        ps.setString(1, newUsername);
                        ps.setInt(2, userId);
                        ps.executeUpdate();
                    }
                }

                // si client => update client fields
                if (clientId != null) {
                    String fn = trimOrNull(update.getFirstName());
                    String ln = trimOrNull(update.getLastName());
                    String email = trimOrNull(update.getEmail());
                    String phone = trimOrNull(update.getPhone());
                    String address = trimOrNull(update.getAddress());

                    // first_name & last_name NOT NULL dans ta BD => on garde l’existant si vide
                    String sqlGetClient = "SELECT first_name, last_name FROM client WHERE id=?";
                    String curFn = null, curLn = null;
                    try (PreparedStatement ps = conn.prepareStatement(sqlGetClient)) {
                        ps.setInt(1, clientId);
                        try (ResultSet rs = ps.executeQuery()) {
                            if (rs.next()) {
                                curFn = rs.getString("first_name");
                                curLn = rs.getString("last_name");
                            }
                        }
                    }
                    if (fn == null) fn = curFn;
                    if (ln == null) ln = curLn;

                    String sqlUpd =
                            "UPDATE client SET first_name=?, last_name=?, email=?, phone=?, address=? WHERE id=?";

                    try (PreparedStatement ps = conn.prepareStatement(sqlUpd)) {
                        ps.setString(1, fn);
                        ps.setString(2, ln);
                        if (email != null) ps.setString(3, email); else ps.setNull(3, Types.VARCHAR);
                        if (phone != null) ps.setString(4, phone); else ps.setNull(4, Types.VARCHAR);
                        if (address != null) ps.setString(5, address); else ps.setNull(5, Types.VARCHAR);
                        ps.setInt(6, clientId);
                        ps.executeUpdate();
                    }
                }

                conn.commit();
                return true;

            } catch (RemoteException e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw e;
            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans updateUserProfile", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans updateUserProfile", e);
        }
    }
    @Override
    public boolean adminResetPassword(int actorUserId, int targetUserId, String newPlainPassword) throws RemoteException {
        if (actorUserId <= 0) throw new RemoteException("actorUserId invalide");
        if (targetUserId <= 0) throw new RemoteException("targetUserId invalide");
        if (newPlainPassword == null || newPlainPassword.trim().isEmpty()) throw new RemoteException("Mot de passe invalide");
        if (newPlainPassword.length() < 4) throw new RemoteException("Mot de passe trop court (min 4)");

        try (Connection conn = DBConnection.getConnection()) {
            conn.setAutoCommit(false);

            try {
                // 1) vérifier acteur super-admin
                boolean actorIsSuper = false;
                try (PreparedStatement ps = conn.prepareStatement("SELECT is_super_admin FROM `user` WHERE id=?")) {
                    ps.setInt(1, actorUserId);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            conn.rollback();
                            throw new RemoteException("Acteur introuvable");
                        }
                        actorIsSuper = rs.getBoolean("is_super_admin");
                    }
                }

                if (!actorIsSuper) {
                    conn.rollback();
                    throw new RemoteException("Accès refusé (super-admin requis)");
                }

                // 2) vérifier cible existe
                try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM `user` WHERE id=?")) {
                    ps.setInt(1, targetUserId);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            conn.rollback();
                            throw new RemoteException("Utilisateur cible introuvable");
                        }
                    }
                }

                // 3) update password + reset locks
                String newHash = hashPassword(newPlainPassword);

                try (PreparedStatement ps = conn.prepareStatement(
                        "UPDATE `user` SET password_hash=?, failed_attempts=0, lock_until=NULL WHERE id=?"
                )) {
                    ps.setString(1, newHash);
                    ps.setInt(2, targetUserId);
                    int updated = ps.executeUpdate();
                    if (updated <= 0) {
                        conn.rollback();
                        return false;
                    }
                }

                conn.commit();
                return true;

            } catch (RemoteException e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw e;
            } catch (Exception e) {
                try { conn.rollback(); } catch (SQLException ignored) {}
                throw new RemoteException("Erreur dans adminResetPassword", e);
            } finally {
                try { conn.setAutoCommit(true); } catch (SQLException ignored) {}
            }

        } catch (SQLException e) {
            throw new RemoteException("Erreur SQL dans adminResetPassword", e);
        }
    }


}
