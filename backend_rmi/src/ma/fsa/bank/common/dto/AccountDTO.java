package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class AccountDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String accountNumber;
    private double balance;

    public AccountDTO() {}

    public AccountDTO(int id, String accountNumber, double balance) {
        this.id = id;
        this.accountNumber = accountNumber;
        this.balance = balance;
    }

    public int getId() { return id; }
    public String getAccountNumber() { return accountNumber; }
    public double getBalance() { return balance; }

    public void setId(int id) { this.id = id; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
    public void setBalance(double balance) { this.balance = balance; }
}
