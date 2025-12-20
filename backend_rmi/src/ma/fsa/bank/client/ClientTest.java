package ma.fsa.bank.client;

import ma.fsa.bank.rmi.interfaces.BankService;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ClientTest {

    public static void main(String[] args) {
        try {

            Registry registry = LocateRegistry.getRegistry("localhost", 1099);


            BankService bankService = (BankService) registry.lookup("BankService");

            String accountNumber = "ACC-001-0001";

            System.out.println("=== Test consultation de solde ===");
            double balanceBefore = bankService.getBalance(accountNumber);
            System.out.println("Solde avant dépôt : " + balanceBefore + " MAD");

            System.out.println("\n=== Test dépôt de 500 MAD ===");
            boolean okDeposit = bankService.deposit(accountNumber, 500);
            System.out.println("Dépôt réussi ? " + okDeposit);

            double balanceAfter = bankService.getBalance(accountNumber);
            System.out.println("Solde après dépôt : " + balanceAfter + " MAD");

            System.out.println("\n=== Test retrait de 1000 MAD ===");
            boolean okWithdraw = bankService.withdraw(accountNumber, 1000);
            System.out.println("Retrait réussi ? " + okWithdraw);

            double balanceFinal = bankService.getBalance(accountNumber);
            System.out.println("Solde final : " + balanceFinal + " MAD");

        } catch (Exception e) {
            System.err.println("[CLIENT] Erreur : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
