package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class AccountLimitsDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private String accountNumber;
    private String clientType;
    private double dailyTransferLimit;
    private double dailyDebitLimit;

    public AccountLimitsDTO() {}

    public AccountLimitsDTO(String accountNumber, String clientType,
                            double dailyTransferLimit, double dailyDebitLimit) {
        this.accountNumber = accountNumber;
        this.clientType = clientType;
        this.dailyTransferLimit = dailyTransferLimit;
        this.dailyDebitLimit = dailyDebitLimit;
    }

    public String getAccountNumber() { return accountNumber; }
    public String getClientType() { return clientType; }
    public double getDailyTransferLimit() { return dailyTransferLimit; }
    public double getDailyDebitLimit() { return dailyDebitLimit; }

    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
    public void setClientType(String clientType) { this.clientType = clientType; }
    public void setDailyTransferLimit(double dailyTransferLimit) { this.dailyTransferLimit = dailyTransferLimit; }
    public void setDailyDebitLimit(double dailyDebitLimit) { this.dailyDebitLimit = dailyDebitLimit; }

    @Override
    public String toString() {
        return "AccountLimitsDTO{accountNumber='" + accountNumber + "', clientType='" + clientType +
                "', dailyTransferLimit=" + dailyTransferLimit + ", dailyDebitLimit=" + dailyDebitLimit + "}";
    }
}
