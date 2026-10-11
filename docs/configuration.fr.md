# Configuration d’une installation

## Accès et conteneurs

`.env` est lu par Docker Compose. `config/config.json` est lu par les
collecteurs. Ces deux fichiers sont privés et exclus de Git.

| Paramètre | Rôle |
| --- | --- |
| `FCP_ADMIN_USER`, `FCP_ADMIN_PASSWORD` | Initialisation du compte seulement ; retirer le mot de passe de l’environnement après initialisation |
| `FCP_FAIL2BAN_CONTAINER` / `container` | Nom du conteneur Fail2ban ; `.env` prioritaire |
| `FCP_CONTAINER` / `fcp_container` | Nom du conteneur FCP ; `.env` prioritaire, utile pour les preuves HTTP |
| `FCP_BIND_ADDRESS`, `FCP_PORT` | Écoute locale et port publiés |
| `TZ` / `timezone` | Fuseau de l’installation et des rapports, UTC par défaut |
| `jails` | Dictionnaire des jails et libellés attendus ; vide : découverte des jails actives |
| `ssh_jails` | Jails dont les bans correspondent effectivement à des échecs SSH ; adapter avant AbuseIPDB |
| `ssh_log` | Chemin du journal SSH **dans le conteneur Fail2ban**, au format ISO 8601 avec fuseau |
| `ssh_port` | Port public du service SSH protégé |
| `sftp_container`, `sftp_port` | Conteneur OpenSSH SFTP facultatif et son port public |
| `http_enabled` | Activer la collecte des preuves HTTP, faux par défaut |
| `web_jail`, `web_log` | Jail web et journal d’accès **dans Fail2ban**, pour la corrélation AbuseIPDB |
| `service_description` | Description exacte des services et ports publics, jointe aux preuves |
| `postfix` | Conteneur du relais mail existant, avec `/usr/sbin/sendmail` |
| `sender`, `recipient` | Expéditeur et destinataire du rapport quotidien, ensuite configurés dans FCP |
| `message_id_domain` | Domaine des Message-ID ; localhost par défaut, adapter à son domaine |
| `output` | Répertoire d’état interne, conserver `/app/automation-state` avec Compose fourni |

Après modification de `.env` ou des noms de conteneurs : recréer les services
avec `docker compose up -d`. Les scripts de collecte relisent le JSON à chaque
exécution. Les champs modifiés dans l’interface sont conservés séparément
sans être écrasés par l’installateur.

## Journaux facultatifs

Le tableau HTTP lit `/app/logs/access.log`. Remplacer le montage `./logs` du
service FCP par le répertoire de journaux voulu en lecture seule ; le fichier
doit être nommé `access.log`, ou adapter `FCP_HTTP_LOG`. Le format attendu est
celui de NPMplus (`[date] … IP … "METHOD path HTTP/version" status`).
L’absence du fichier ne bloque pas l’administration Fail2ban.

Le relais de journaux SSH/SFTP est propre à chaque déploiement : FCP ne lit pas
automatiquement le journal système de l’hôte. Le journal indiqué dans
`ssh_log` doit déjà être disponible dans le conteneur Fail2ban. Les logs SFTP
sont lus depuis les journaux Docker timestampés du conteneur configuré.
Un journal absent ne devient jamais une preuve inventée.

## Automatisations

1. Configurer le relais Postfix, les adresses et les sources de preuves.
2. Renseigner les jails SSH et web réellement correspondantes.
3. Lancer `docker compose --profile automations up -d --build`.
4. Ouvrir Configuration → Automatisations et activer les fonctions
   voulues : rapport quotidien et/ou AbuseIPDB.

Le worker vérifie les récidives toutes les cinq minutes. Le rapport est tenté
une fois par jour après 08 h, dans le fuseau configuré. Après une interruption,
un rapport du jour peut être tenté au redémarrage. Une tentative de rapport
quotidien en échec n’est pas automatiquement répétée le même jour.

Conserver `state/` lors des mises à jour : les soumissions API incertaines bloquent les renvois automatiques. Les preuves excluent les noms d’utilisateurs, mots de passe, paramètres d’URL et chemins arbitraires.

AbuseIPDB nécessite `config/abuseipdb.key` (mode 600), avec uniquement la clé.
La classification SSH dépend de `ssh_jails` et des filtres de l’opérateur ; les
signalements web nécessitent une corrélation avec des chemins de scan connus.
Les seuls codes HTTP 401/403 ne suffisent pas.

Le webhook facultatif permet uniquement un test manuel. La diffusion automatique des événements n’est pas implémentée.

## Géolocalisation

Aucune base MMDB n’est livrée. La mise à jour de l’interface télécharge
DB-IP City Lite. La base ASN facultative doit être fournie dans `geo/asn.mmdb`.
Les données DB-IP Lite restent sous CC BY 4.0, avec attribution DB-IP dans
l’interface : https://db-ip.com/db/lite.php.

[Authentification, HTTPS et mode HTTP local](authentication.fr.md)

[Fail2ban connection modes / Modes de connexion à Fail2ban](connection.fr.md)
