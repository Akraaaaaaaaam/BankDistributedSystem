BankDistributedSystem (AtlasBank)

Projet académique de système bancaire distribué réalisé dans le cadre du Master d’Excellence FSA IL.

Le système repose sur une architecture distribuée combinant :
- une interface web Django
- un backend Java RMI
- une base de données MySQL

Architecture Générale

L’architecture suit le modèle suivant :

Frontend Web (Django)
→ Client RMI Java (appelé via subprocess / CLI JSON)
→ Serveur RMI Java
→ Base de données MySQL

Structure du projet

- frontend_django/
  - Interface web (authentification, OTP, opérations bancaires, administration)
- backend_rmi/
  - Serveur RMI Java
  - Interfaces distantes
  - Logique métier bancaire
- config/
  - Configuration de la base de données (db.properties)

Fonctionnalités principales

Côté Client
- Authentification avec OTP
- Consultation des comptes
- Dépôt, retrait, virement
- Historique des transactions
- Export CSV

Côté Administration
- Gestion des utilisateurs (CLIENT / ADMIN / EMPLOYEE)
- Activation / désactivation des comptes
- Fermeture de comptes bancaires
- Réinitialisation de mot de passe (super-admin)
- Journal de sécurité
- Statistiques globales

Technologies utilisées

- Java (RMI, JDBC)
- Python (Django)
- MySQL
- HTML / CSS / JavaScript
- GitHub (gestion de version)

Lancement du projet (local)

1. Base de données MySQL
- Importer le schéma SQL
- Configurer `config/db.properties`

2. Serveur RMI Java
- Lancer le registre RMI
- Exécuter `ServerMain`

3. Interface Web Django
```bash
cd frontend_django
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
