package ma.fsa.bank.server;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class DBConnection {

    private static final String PROPERTIES_FILE = "config/db.properties";

    private static String url;
    private static String user;
    private static String password;
    private static String driverClassName;
    private static boolean initialized = false;

    /**
     * Charge la configuration depuis config/db.properties
     */
    private static void loadConfiguration() {
        Properties props = new Properties();

        try (FileInputStream fis = new FileInputStream(PROPERTIES_FILE)) {
            props.load(fis);

            url = props.getProperty("db.url");
            user = props.getProperty("db.user");
            password = props.getProperty("db.password");
            driverClassName = props.getProperty("db.driver");

            if (url == null || user == null || password == null || driverClassName == null) {
                throw new RuntimeException("Configuration DB incomplète dans " + PROPERTIES_FILE);
            }

            // Chargement de la classe driver JDBC
            Class.forName(driverClassName);

            initialized = true;
            System.out.println("[DB] Configuration chargée et driver initialisé.");

        } catch (IOException e) {
            throw new RuntimeException("Erreur lors de la lecture du fichier " + PROPERTIES_FILE, e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("Driver JDBC introuvable : " + driverClassName, e);
        }
    }

    /**
     * Retourne une nouvelle connexion à la base MySQL.
     */
    public static Connection getConnection() throws SQLException {
        if (!initialized) {
            loadConfiguration();
        }

        return DriverManager.getConnection(url, user, password);
    }
}
