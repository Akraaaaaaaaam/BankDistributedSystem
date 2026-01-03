package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class AccountDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String accountNumber;
    private double balance;

    private String type;
    private String currency;
    private String status;
    private String branchName;

    public AccountDTO() {}

    public AccountDTO(int id, String accountNumber, double balance) {
        this.id = id;
        this.accountNumber = accountNumber;
        this.balance = balance;
    }

    public AccountDTO(int id, String accountNumber, double balance,
                      String type, String currency, String status, String branchName) {
        this.id = id;
        this.accountNumber = accountNumber;
        this.balance = balance;
        this.type = type;
        this.currency = currency;
        this.status = status;
        this.branchName = branchName;
    }

    public int getId() { return id; }
    public String getAccountNumber() { return accountNumber; }
    public double getBalance() { return balance; }

    public String getType() { return type; }
    public String getCurrency() { return currency; }
    public String getStatus() { return status; }
    public String getBranchName() { return branchName; }

    public void setId(int id) { this.id = id; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
    public void setBalance(double balance) { this.balance = balance; }

    public void setType(String type) { this.type = type; }
    public void setCurrency(String currency) { this.currency = currency; }
    public void setStatus(String status) { this.status = status; }
    public void setBranchName(String branchName) { this.branchName = branchName; }
}
