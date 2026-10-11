# Connexion à Fail2ban

Dans **Administration de l’application → Connexion à Fail2ban**, choisir Docker
local ou Linux natif local. La détection propose des chemins accessibles depuis
FCP. Tester contrôle la réponse du service, les jails, les droits sur la
configuration, sa validation et la lecture des journaux. Aucun ban, rechargement
ou installation n’est déclenché par ce test.

L’enregistrement reteste les paramètres. Une connexion impossible ou des droits
insuffisants pour l’accès demandé conservent les réglages actifs. Une connexion
en consultation est enregistrable explicitement ; FCP bloque alors les
opérations de modification. Le fichier privé `data/connection.json` est atomique,
avec contrôle des modifications concurrentes. Aucun redémarrage FCP n’est requis.
Le mode Docker utilise par défaut `FCP_FAIL2BAN_CONTAINER` si aucun choix n’est
encore enregistré. Après enregistrement, le formulaire est prioritaire.

## Docker

Nom du conteneur, accès au socket Docker. L’édition de configuration garde la
structure crazymax/fail2ban `/data` et `/etc/fail2ban`. Un autre agencement
peut permettre la consultation mais refuser l’administration ; le test l’indique.

## Fail2ban Linux natif

FCP appelle directement `fail2ban-client -c DOSSIER -s SOCKET`, sans Docker,
shell ou sudo implicite. `fail2ban-client` et `fail2ban-regex` doivent être
installés, avec une version compatible avec le serveur. L’image FCP inclut
le paquet client Fail2ban pour ce mode ; aucun daemon natif n’est démarré.

Valeurs habituelles : `/etc/fail2ban`, `/run/fail2ban/fail2ban.sock`,
`/var/log/fail2ban.log`. Le journal système est aussi proposé, si `journalctl`
est disponible et autorisé. Le fichier est lu avec une limite de 32 Mio et
100 000 lignes ; ce n’est pas un export exhaustif des journaux archivés.

Si FCP reste dans Docker, monter les chemins de l’hôte dans son conteneur :
configuration (lecture seule pour consultation, écriture pour édition), dossier
du socket Fail2ban et journaux. Monter le dossier du socket plutôt que son
fichier permet de suivre sa recréation. Les chemins de logs mentionnés par les
jails doivent également être accessibles pour la validation de configuration.
Les chemins saisis dans FCP sont ceux du conteneur. Les jails rechargées par le
client doivent garder des chemins cohérents avec l’hôte.

L’accès au socket Fail2ban donne des pouvoirs importants sur son daemon : le
mode consultation est une restriction FCP, pas une séparation de droits du
protocole Fail2ban. Ne pas donner un accès administrateur à des utilisateurs
non fiables. FCP ne modifie ni les groupes, ni les permissions, ni sudoers.

L’édition native conserve les fichiers de distribution et leurs permissions.
Privilégier `.local` pour personnaliser filtres/actions ; leur `.conf` de base
n’est pas supprimable depuis FCP. Toute sauvegarde/restauration est testée sur
une copie avant application. Les originaux, métadonnées et empreintes sont
conservés sous `data/fail2ban-backups/IDENTIFIANT/ui`. Un échec de rechargement
restaure le fichier et tente de recharger la version précédente.

Démarrer/arrêter/redémarrer le service utilise `systemctl ... fail2ban.service`
uniquement lorsque FCP fonctionne directement sur l’hôte. Depuis Docker,
utiliser l’hôte pour ces trois opérations ; recharger la configuration et les
jails reste possible. Une autorisation système manquante reste un refus explicite.

## Exécuter FCP sans Docker

Sur Linux, installer Fail2ban, Python 3, les dépendances de `requirements.txt`
dans un environnement Python dédié, puis lancer `gunicorn --config
gunicorn.conf.py ui:app` depuis `src` avec `PYTHONPATH` pointant sur `src` et le
chemin absolu du fichier Gunicorn. Un gestionnaire de service peut superviser
ce processus sous un compte dédié. Définir au minimum les chemins persistants :

- `FCP_AUTH_DATABASE=/var/lib/fcp/auth.sqlite3`
- `FCP_CONNECTION_FILE=/var/lib/fcp/connection.json`
- `FCP_AUTOMATION_FILE=/var/lib/fcp/automation.json`
- `FCP_DATABASE=/var/lib/fcp/fcp.sqlite3`
- `FCP_WEBHOOK_SETTINGS=/var/lib/fcp/webhook-settings.sqlite3`
- `FCP_CONFIG=/etc/fcp/config.json`

Préparer ces dossiers avec les droits du compte FCP. L’authentification conserve
ses exigences existantes : mot de passe initial privé, HTTPS par défaut ou
option HTTP local explicite, restriction réseau. Le port Gunicorn reste 9191.
Le processus web n’a pas besoin d’un accès Docker en mode natif. Les fonctions
optionnelles liées à `/app/geo`, au journal HTTP et aux envois automatiques
nécessitent leur propre configuration ; elles ne sont pas installées par ce menu.

## Automatisations

Les scripts AbuseIPDB et les planificateurs externes gardent leur propre
configuration. Ce formulaire change la cible de l’administration web, pas celle
d’un service externe. Sur Ramsès, les timers existants et leurs protections
contre les doublons sont conservés. Aucun transfert automatique des historiques
ou des signalements entre deux installations Fail2ban n’est effectué.
