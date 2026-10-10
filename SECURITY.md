# Sécurité d’exploitation

FCP administre des bannissements et des fichiers de sécurité. Le socket Docker
lui donne des pouvoirs d’administration sur l’hôte ; un montage `:ro` du socket
ne supprimerait pas ces pouvoirs. Installer uniquement sur un hôte de
confiance, avec des utilisateurs administrateurs autorisés.

Toutes les routes exigent une authentification HTTP Basic ; le jeton de
l’interface complète cette authentification pour les opérations sensibles.
HTTP Basic exige HTTPS dès que l’accès quitte la machine locale. Le Compose
fourni écoute sur 127.0.0.1. Ne pas exposer directement ce port sur Internet.

Conserver le mode privé des fichiers `.env`, `config`, `data` et `state`.
Ne publier ni journaux, ni adresses observées, ni messages réels, ni exports
SQLite, ni clés, ni sauvegardes. `.gitignore` ne protège pas les fichiers déjà
suivis par Git : contrôler la liste des fichiers avant publication.

Pour un problème de sécurité, contacter le mainteneur par un canal privé.
Ne pas joindre de secrets ou de journaux réels à une issue publique.
