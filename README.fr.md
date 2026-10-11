# FCP — Fail2ban Control Panel

[English](README.md) · [Français](README.fr.md)

Interface web de gestion de Fail2ban : vue d’ensemble, jails, filtres, actions,
historique, carte mondiale des IP et signalements facultatifs à AbuseIPDB.

FCP peut administrer un **Fail2ban existant dans Docker ou installé directement
sur Linux**. Le choix se fait dans **Réglages → Connexion Fail2ban**, avec détection, test et accès en consultation ou administration.
Voir [Connexion à Fail2ban](docs/connection.fr.md), notamment pour exécuter FCP
sans Docker. FCP n’installe pas Fail2ban et conserve ses règles existantes.
L’accès à un serveur distant n’est pas pris en charge dans cette version.

## Installation

Prérequis : Python 3 pour préparer les fichiers, Docker Engine, Docker Compose,
un conteneur Fail2ban avec `fail2ban-client`, `fail2ban-regex`, Python 3 et `date`.
La gestion persistante des fichiers cible l’organisation de crazymax/fail2ban :
`/data/{jail.d,filter.d,action.d}` et `/etc/fail2ban`. D’autres images doivent
être vérifiées avant d’utiliser l’édition de configuration.

```sh
git clone https://github.com/woofix/fcp.git
cd fcp
python3 install.py
```

L’installateur crée `.env` avec un mot de passe aléatoire et
`config/config.json` sans adresses personnelles. Il préserve les fichiers
existants. Dans `.env`, renseigner `FCP_FAIL2BAN_CONTAINER` avec le nom du
conteneur Fail2ban. Adapter les options décrites dans [Configuration](docs/configuration.md).

```sh
docker compose config --quiet
docker compose up -d --build
```

Configurer un accès HTTPS avant d’ouvrir FCP : voir [l’authentification](docs/authentication.fr.md). Le mot de passe initial est dans `.env`, à retirer après initialisation. Le test HTTP local exige explicitement `FCP_ALLOW_HTTP=1`.
Le port est local par défaut. Pour un serveur distant, utiliser un tunnel SSH
ou un reverse proxy HTTPS authentifié. Voir [Sécurité](SECURITY.md).

Les répertoires `data`, `state`, `config`, `geo` et `logs` sont persistants et
exclus de Git. Leur sauvegarde est à la charge de l’opérateur.

## Navigation

Le menu de gauche reste visible dans toute l’application. Cliquer sur une
rubrique ouvre son sous-menu et met en évidence la vue sélectionnée.

| Rubrique | Vues et réglages |
| --- | --- |
| Tableau de bord | État du service, compteurs des protections, activité récente |
| Bannissements | Liste, Carte mondiale, Historique |
| Activité | Détections, Requêtes HTTP, Journal Fail2ban |
| Protections | Jails, Filtres et actions, Sauvegardes, Service, Expert |
| Automatisations | Signalements facultatifs AbuseIPDB et rapport quotidien |
| Réglages | Général, Connexion Fail2ban, Sécurité |

Les vues Liste, Carte mondiale et Historique conservent les mêmes filtres de
protection, pays, état et recherche lors du passage d’une vue à l’autre.
La carte se trouve dans **Bannissements**, sans entrée séparée dans le menu.
Le mot de passe, les sessions et le journal de sécurité sont accessibles dans
**Réglages → Sécurité**.

Voir le [guide d’utilisation](docs/usage.fr.md), avec la procédure de mise à jour.

## Options

- **HTTP** : facultatif, format NPMplus compatible, fichier monté à
  `/app/logs/access.log`. Aucun journal d’exemple réel n’est distribué.
- **Carte mondiale** : fond intégré ; placer sa base MMDB dans `geo/city.mmdb` ou
  utiliser la mise à jour DB-IP de l’interface. Une IP sans coordonnées reste
  non localisée. Les bases ne sont pas incluses.
- **Automatisations** : profil facultatif `automations`, contrôles désactivés
  par défaut. Voir [Configuration](docs/configuration.md) avant de les activer.
- **Rapport quotidien** : synthèse envoyée à votre propre adresse via un conteneur Postfix existant.
- **AbuseIPDB** : facultatif, clé privée dans un fichier local ; aucune clé
  n’est intégrée au dépôt.
- **Webhook facultatif** : configuration et test manuel ; aucun événement automatique n’est envoyé dans cette version.

## Validation

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

L’image utilise Python 3.12. Les tests hors réseau vérifient l’authentification,
les noms de conteneurs configurés, l’absence de sources facultatives, les
preuves, la suppression des données privées et les protections contre les
renvois. Une nouvelle installation doit aussi être vérifiée avec ses propres
jails, journaux et règles de pare-feu avant activation des signalements.

## Licence

Code FCP : **Apache-2.0**, voir [LICENSE](LICENSE) et [NOTICE](NOTICE).
Les dépendances et les données facultatives conservent leurs licences propres.

Résultats et limites des vérifications : [Validation](docs/validation.md).
Préparation du dépôt distant : [Publication GitHub](docs/publication.md).

## Langues

Le choix **Français / English** se trouve dans **Réglages → Général** et est conservé dans un cookie pendant un an.
Les journaux techniques, fichiers de configuration et valeurs saisies gardent leur contenu original.

[Authentification et sessions](docs/authentication.fr.md)
