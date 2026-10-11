# Validation

38 tests automatiques réussissent sur Linux/Python 3.12 et macOS/Python 3.9 :
sessions, CSRF, origine, restrictions réseau, changement de mot de passe,
limitation des tentatives, langues, confidentialité des preuves, installation
sans écrasement, connexion persistante, conflits de révision, consultation
seule et retour arrière de configuration native.

L’image Docker a été construite et démarrée. Le connecteur Docker a été vérifié
sur un Fail2ban existant avec trois jails actives. Le mode natif a été testé sur
un vrai Fail2ban 1.1.0 isolé : état, inventaire, validation, sauvegarde,
rechargement, restauration, tableau de bord et ban/déban avec action fictive.
Ce test n’avait ni réseau ni accès au pare-feu de l’hôte. Aucun mail réel ou
signalement API n’a été envoyé par ces tests. L’interface française et
anglaise et l’alignement des champs ont été vérifiés dans le navigateur.

Ces essais ne couvrent pas plusieurs distributions ou architectures. Le client
natif doit être compatible avec le daemon et accéder aux fichiers, socket et
journaux. Les montages et permissions système ne sont pas créés automatiquement.
Les planificateurs externes gardent leur configuration indépendante ; changer
la connexion web ne les déplace pas. L’administration distante, plusieurs
comptes administrateurs et les notifications webhook automatiques ne sont pas
implémentés. Vérifier GitHub Actions pour chaque commit publié.

Le regroupement du menu a été vérifié dans un aperçu navigateur isolé : Bannissements ouvre Liste, Carte mondiale et Historique ; Activité, Protections et Réglages ouvrent leurs sous-menus à gauche. Le filtre de recherche a été conservé entre les vues des bannissements. L’image mise à jour a été installée sur le serveur de test et déclarée saine ; les données Fail2ban existantes restaient lisibles. Les contrôles navigateur utilisaient des données de test isolées, sans modifier les bans ni les identifiants réels.
