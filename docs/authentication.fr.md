# Authentification et administration de FCP


Le mot de passe est haché avec Argon2id dans `/app/data/auth.sqlite3` (permissions 0600). Les cookies contiennent uniquement un identifiant aléatoire ; les identifiants de session sont hachés dans la base. Les sessions expirent après 30 minutes d’inactivité ou 8 heures maximum. Un changement de mot de passe ferme toutes les sessions. Le mot de passe doit contenir 20 à 256 caractères.

Après 5 échecs depuis une adresse, la connexion est bloquée 15 minutes. Une limite globale de 30 échecs protège aussi contre les tentatives réparties. Ces limites persistent après redémarrage. Les requêtes de connexion et de gestion de compte utilisent des jetons CSRF et une vérification d’origine. La protection CSRF existante de Fail2ban est conservée.


## Transport

Par défaut, FCP refuse la connexion en HTTP. Derrière un proxy HTTPS, publie uniquement le port local `127.0.0.1:9191`, définis `FCP_PUBLIC_URL=https://ton-nom` et `FCP_TRUST_PROXY=1` uniquement si le proxy est le seul à pouvoir joindre ce port. Il doit remplacer les en-têtes X-Forwarded-For et X-Forwarded-Proto. Les cookies portent Secure, HttpOnly et SameSite=Lax. Le mode proxy ne doit jamais être activé sur un port directement accessible.

Pour un test local, `FCP_ALLOW_HTTP=1` autorise explicitement HTTP : les échanges et le cookie de session ne sont pas chiffrés, et le cookie ne porte pas Secure. Ne pas exposer ce mode publiquement. Lier le port à une interface locale et limiter les sources avec `FCP_ALLOWED_NETWORKS`.

## Initialisation et récupération

`FCP_ADMIN_PASSWORD` n’est utilisé qu’à la première création de la base d’authentification. Retire ensuite ce secret de `.env` et recrée le conteneur pour l’enlever de son environnement. Ne supprime pas la base pour changer le mot de passe.

En cas de perte d’accès, depuis la console de confiance du serveur :

```
docker exec -it fcp python /app/automation/reset-admin.py
```



La connexion utilise un identifiant et un mot de passe. La double authentification n’est pas proposée dans cette version.

Les commandes du compte sont dans **Réglages → Sécurité** : changement du mot de passe, fermeture des sessions, déconnexion et journal de sécurité. La langue est dans **Réglages → Général**, et le connecteur dans **Réglages → Connexion Fail2ban**. Voir le [guide d’utilisation](usage.fr.md).
