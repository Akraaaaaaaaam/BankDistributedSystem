package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class AdminGlobalStatsDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int totalUsers;
    private int totalClients;
    private int totalAdmins;
    private int totalBranches;
    private int activeAccounts;
    private int closedAccounts;

    private long totalTransactions;

    private long totalDepositsCount;
    private double totalDepositsAmount;

    private long totalWithdrawalsCount;
    private double totalWithdrawalsAmount;

    private long totalTransfersCount;
    private double totalTransfersAmount;

    public AdminGlobalStatsDTO() {}

    public AdminGlobalStatsDTO(
            int totalUsers,
            int totalClients,
            int totalAdmins,
            int totalBranches,
            int activeAccounts,
            int closedAccounts,
            long totalTransactions,
            long totalDepositsCount,
            double totalDepositsAmount,
            long totalWithdrawalsCount,
            double totalWithdrawalsAmount,
            long totalTransfersCount,
            double totalTransfersAmount
    ) {
        this.totalUsers = totalUsers;
        this.totalClients = totalClients;
        this.totalAdmins = totalAdmins;
        this.totalBranches = totalBranches;
        this.activeAccounts = activeAccounts;
        this.closedAccounts = closedAccounts;
        this.totalTransactions = totalTransactions;
        this.totalDepositsCount = totalDepositsCount;
        this.totalDepositsAmount = totalDepositsAmount;
        this.totalWithdrawalsCount = totalWithdrawalsCount;
        this.totalWithdrawalsAmount = totalWithdrawalsAmount;
        this.totalTransfersCount = totalTransfersCount;
        this.totalTransfersAmount = totalTransfersAmount;
    }

    public int getTotalUsers() { return totalUsers; }
    public int getTotalClients() { return totalClients; }
    public int getTotalAdmins() { return totalAdmins; }
    public int getTotalBranches() { return totalBranches; }
    public int getActiveAccounts() { return activeAccounts; }
    public int getClosedAccounts() { return closedAccounts; }

    public long getTotalTransactions() { return totalTransactions; }

    public long getTotalDepositsCount() { return totalDepositsCount; }
    public double getTotalDepositsAmount() { return totalDepositsAmount; }

    public long getTotalWithdrawalsCount() { return totalWithdrawalsCount; }
    public double getTotalWithdrawalsAmount() { return totalWithdrawalsAmount; }

    public long getTotalTransfersCount() { return totalTransfersCount; }
    public double getTotalTransfersAmount() { return totalTransfersAmount; }

    public void setTotalUsers(int totalUsers) { this.totalUsers = totalUsers; }
    public void setTotalClients(int totalClients) { this.totalClients = totalClients; }
    public void setTotalAdmins(int totalAdmins) { this.totalAdmins = totalAdmins; }
    public void setTotalBranches(int totalBranches) { this.totalBranches = totalBranches; }
    public void setActiveAccounts(int activeAccounts) { this.activeAccounts = activeAccounts; }
    public void setClosedAccounts(int closedAccounts) { this.closedAccounts = closedAccounts; }

    public void setTotalTransactions(long totalTransactions) { this.totalTransactions = totalTransactions; }

    public void setTotalDepositsCount(long totalDepositsCount) { this.totalDepositsCount = totalDepositsCount; }
    public void setTotalDepositsAmount(double totalDepositsAmount) { this.totalDepositsAmount = totalDepositsAmount; }

    public void setTotalWithdrawalsCount(long totalWithdrawalsCount) { this.totalWithdrawalsCount = totalWithdrawalsCount; }
    public void setTotalWithdrawalsAmount(double totalWithdrawalsAmount) { this.totalWithdrawalsAmount = totalWithdrawalsAmount; }

    public void setTotalTransfersCount(long totalTransfersCount) { this.totalTransfersCount = totalTransfersCount; }
    public void setTotalTransfersAmount(double totalTransfersAmount) { this.totalTransfersAmount = totalTransfersAmount; }

    @Override
    public String toString() {
        return "AdminGlobalStatsDTO{totalUsers=" + totalUsers +
                ", totalClients=" + totalClients +
                ", totalAdmins=" + totalAdmins +
                ", totalBranches=" + totalBranches +
                ", activeAccounts=" + activeAccounts +
                ", closedAccounts=" + closedAccounts +
                ", totalTransactions=" + totalTransactions + "}";
    }
}
