package ma.fsa.bank.server;

import ma.fsa.bank.rmi.interfaces.BankService;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.sql.Connection;

public class ServerMain {

    public static void main(String[] args) {

        try {

            try (Connection conn = DBConnection.getConnection()) {
                System.out.println("[DB] Connexion MySQL OK.");
            }


            BankService bankService = new BankServiceImpl();


            Registry registry = LocateRegistry.createRegistry(1099);


            registry.rebind("BankService", bankService);

            System.out.println("[RMI] Serveur BankService prêt sur le port 1099.");

        } catch (Exception e) {
            System.err.println("[RMI] Erreur au démarrage du serveur : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
