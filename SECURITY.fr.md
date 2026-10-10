# Sécurité

L’authentification Basic est remplacée par des sessions révocables et des mots de passe Argon2id. Toutes les routes métier sont protégées ; seuls la connexion, le choix de langue et un contrôle de santé minimal en boucle locale sont accessibles sans connexion. Voir [l’authentification et ses limites](docs/authentication.fr.md).

HTTPS est requis par défaut. Le mode de test HTTP local doit être explicitement autorisé et ne chiffre pas les échanges. Le socket Docker donne des pouvoirs importants sur l’hôte : réserver FCP aux administrateurs de confiance. Les données et secrets locaux ne doivent jamais être publiés dans Git.
