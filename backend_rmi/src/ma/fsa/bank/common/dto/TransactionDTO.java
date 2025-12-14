package ma.fsa.bank.common.dto;

import java.io.Serializable;
import java.util.Date;

public class TransactionDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private long id;
    private String type;
    private double amount;
    private double balanceAfter;
    private Date date;
    private String accountNumber;
    private String branchName;

    public TransactionDTO() {}

    public TransactionDTO(long id, String type, double amount, double balanceAfter, Date date) {
        this(id, type, amount, balanceAfter, date, null, null);
    }

    public TransactionDTO(long id, String type, double amount, double balanceAfter, Date date, String accountNumber) {
        this(id, type, amount, balanceAfter, date, accountNumber, null);
    }

    public TransactionDTO(long id, String type, double amount, double balanceAfter, Date date, String accountNumber, String branchName) {
        this.id = id;
        this.type = type;
        this.amount = amount;
        this.balanceAfter = balanceAfter;
        this.date = date;
        this.accountNumber = accountNumber;
        this.branchName = branchName;
    }

    public long getId() { return id; }
    public String getType() { return type; }
    public double getAmount() { return amount; }
    public double getBalanceAfter() { return balanceAfter; }
    public Date getDate() { return date; }
    public String getAccountNumber() { return accountNumber; }
    public String getBranchName() { return branchName; }

    public void setId(long id) { this.id = id; }
    public void setType(String type) { this.type = type; }
    public void setAmount(double amount) { this.amount = amount; }
    public void setBalanceAfter(double balanceAfter) { this.balanceAfter = balanceAfter; }
    public void setDate(Date date) { this.date = date; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
    public void setBranchName(String branchName) { this.branchName = branchName; }

    @Override
    public String toString() {
        return "TransactionDTO{id=" + id + ", type='" + type + "', amount=" + amount +
                ", balanceAfter=" + balanceAfter + ", date=" + date +
                ", accountNumber='" + accountNumber + "', branchName='" + branchName + "'}";
    }
}
