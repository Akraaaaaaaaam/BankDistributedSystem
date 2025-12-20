package ma.fsa.bank.rmi.interfaces;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

import ma.fsa.bank.common.dto.*;

public interface BankService extends Remote {


    RegisterResponse registerUser(RegisterRequest req) throws RemoteException;
    UserDTO authenticate(String username, String password) throws RemoteException;


    double getBalance(String accountNumber) throws RemoteException;
    boolean deposit(String accountNumber, double amount) throws RemoteException;
    boolean withdraw(String accountNumber, double amount) throws RemoteException;
    boolean transfer(String fromAccount, String toAccount, double amount) throws RemoteException;

    AccountDTO getAccount(String accountNumber) throws RemoteException;
    List<TransactionDTO> getTransactions(String accountNumber) throws RemoteException;
    List<AccountDTO> getClientAccounts(int clientId) throws RemoteException;
    boolean closeAccount(String accountNumber) throws RemoteException;


    List<UserDTO> listUsers() throws RemoteException;
    UserDTO createAdminUser(String username, String plainPassword) throws RemoteException;
    boolean setUserActive(int userId, boolean active) throws RemoteException;


    boolean adminResetPassword(int actorUserId, int targetUserId, String newPlainPassword) throws RemoteException;


    AdminGlobalStatsDTO getAdminGlobalStats() throws RemoteException;
    List<TransactionDTO> getAllTransactions() throws RemoteException;


    List<BranchDTO> listBranches() throws RemoteException;
    AccountDTO createAccount(int clientId, int branchId, String type, String currency) throws RemoteException;


    String getClientType(int clientId) throws RemoteException;
    boolean setClientType(int clientId, String clientType) throws RemoteException;
    AccountLimitsDTO getAccountLimits(String accountNumber) throws RemoteException;


    UserProfileDTO getUserProfile(int userId) throws RemoteException;
    boolean updateUserProfile(UserProfileUpdateDTO update) throws RemoteException;
}
