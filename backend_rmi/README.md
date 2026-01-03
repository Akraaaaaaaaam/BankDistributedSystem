BankDistributedSystem (AtlasBank)

Ce projet s’inscrit dans le cadre du Master d’Excellence à la Faculté des Sciences d’Agadir, filière Informatique et Logiciels (IL). Il consiste en la conception et la réalisation d’un système bancaire distribué permettant la gestion sécurisée des utilisateurs, des comptes bancaires et des transactions financières.

L’objectif principal du projet est de mettre en pratique les concepts étudiés en systèmes distribués, notamment la communication entre composants distants, la séparation des responsabilités et l’intégration de plusieurs technologies au sein d’une même application.

Le système repose sur une architecture distribuée composée de trois parties principales. Une interface web développée avec Django assure la couche présentation et l’interaction avec les utilisateurs. Cette interface communique avec un client Java qui invoque, via Java RMI, des services distants exposés par un serveur Java. Le serveur RMI implémente la logique métier bancaire et interagit avec une base de données relationnelle MySQL pour assurer la persistance des données.

L’architecture globale peut être résumée comme suit : l’utilisateur interagit avec l’application web Django, qui transmet les requêtes au client Java RMI. Celui-ci appelle les méthodes distantes du serveur RMI, lequel traite les opérations bancaires et accède à la base de données MySQL.

Le projet est structuré en deux modules principaux. Le module backend_rmi contient l’ensemble des composants Java, incluant les interfaces RMI, l’implémentation du serveur, le client RMI ainsi que les objets de transfert de données. Le module frontend_django regroupe l’application web Django, comprenant les vues, les formulaires, les templates, les fichiers statiques et la configuration du projet.

Du point de vue fonctionnel, le système permet aux clients de s’authentifier de manière sécurisée avec un mécanisme d’OTP, de consulter leurs comptes bancaires, d’effectuer des dépôts, des retraits et des virements, ainsi que de consulter l’historique de leurs transactions. Les utilisateurs peuvent également exporter leurs transactions au format CSV et gérer certaines informations de leur profil.

Le système intègre également une partie administration. Les administrateurs peuvent gérer les utilisateurs du système selon les rôles existants, à savoir client, administrateur et super-administrateur. Ils disposent de fonctionnalités permettant l’activation ou la désactivation des utilisateurs, la fermeture des comptes bancaires, la consultation globale des transactions et l’accès à des statistiques générales. Certaines opérations sensibles, comme la réinitialisation des mots de passe, sont réservées au super-administrateur. Le système conserve également un journal des actions importantes à des fins de suivi et de sécurité.

Les technologies utilisées dans ce projet sont Java pour la partie distribuée avec Java RMI et JDBC, Python avec le framework Django pour l’interface web, MySQL pour la base de données, ainsi que HTML, CSS et JavaScript pour la présentation. Le projet est versionné à l’aide de Git et hébergé sur GitHub afin d’assurer le suivi des modifications et la traçabilité du travail réalisé.

Le déploiement du projet en environnement local nécessite la configuration de la base de données MySQL, le lancement du serveur Java RMI et le démarrage de l’application web Django. Une fois ces composants en fonctionnement, l’utilisateur peut accéder à l’application via un navigateur web.
