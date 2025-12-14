package ma.fsa.bank.server;

import ma.fsa.bank.rmi.interfaces.BankService;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.sql.Connection;

public class ServerMain {

    public static void main(String[] args) {

        try {
            // Juste pour vérifier que la base est OK
            try (Connection conn = DBConnection.getConnection()) {
                System.out.println("[DB] Connexion MySQL OK.");
            }

            // Création de l'implémentation du service
            BankService bankService = new BankServiceImpl();

            // Création du registre RMI sur le port 1099
            Registry registry = LocateRegistry.createRegistry(1099);

            // Publication du service sous le nom "BankService"
            registry.rebind("BankService", bankService);

            System.out.println("[RMI] Serveur BankService prêt sur le port 1099.");

        } catch (Exception e) {
            System.err.println("[RMI] Erreur au démarrage du serveur : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
