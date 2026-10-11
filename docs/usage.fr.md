# Guide d’utilisation

[English](usage.md) · [Français](usage.fr.md)

## Utilisation quotidienne

Cliquer sur une rubrique du menu de gauche ouvre son sous-menu. Le tableau de
bord résume l’état du service et les compteurs ; consulter Bannissements pour
les détails des IP.

- **Bannissements → Liste** : rechercher une adresse, filtrer par protection,
  pays ou état, puis sélectionner une IP pour consulter ses informations et
  les actions de ban/déban disponibles.
- **Bannissements → Carte mondiale** : explorer les positions approximatives.
  Les IP sans coordonnées restent dans la liste. Une position ne prouve pas
  l’identité d’une personne.
- **Bannissements → Historique** : consulter les événements Ban/Unban par date
  avec les mêmes filtres. Cliquer sur une IP ouvre ses détails dans la carte.
- **Activité** : détections, requêtes HTTP et journal Fail2ban. Les requêtes
  nécessitent des journaux compatibles montés ; une source absente ne produit
  pas de données fictives.
- **Protections** : jails, filtres/actions, sauvegardes de configuration,
  état du service et commandes Expert. Les possibilités dépendent du mode
  de connexion et de l’accès consultation/administration choisi.
- **Automatisations** : intégration facultative AbuseIPDB et rapport quotidien.
  Consulter les prérequis de [Configuration](configuration.fr.md).
- **Réglages → Général** : choix du français ou de l’anglais.
- **Réglages → Connexion Fail2ban** : Docker ou Linux natif, détection des
  chemins, test et enregistrement. Voir [Connexion](connection.fr.md).
- **Réglages → Sécurité** : mot de passe, fermeture des autres sessions,
  déconnexion et journal de sécurité. Changer le mot de passe ferme toutes
  les sessions.

L’état des bans est vérifié auprès de Fail2ban. L’historique se limite aux
5 000 dernières lignes consultées, à 300 anciennes entrées IP et à 300
événements ; ce n’est pas une archive complète. Les filtres sont conservés
entre les trois vues dans la page ouverte ; leur valeur peut être réinitialisée
au rechargement. La rubrique principale et la vue des bannissements sont
mémorisées dans le navigateur.

## Mise à jour d’une installation Docker existante

Sauvegarder les données persistantes et les réglages privés, noter la révision
Git et l’image actuelles, puis vérifier les modifications locales avant de
récupérer la mise à jour. Conserver `.env`, `config/`, `data/`, `state/`, `geo/`,
`logs/` et les fichiers Compose locaux.

Depuis le dépôt existant, avec le même projet Compose et ses fichiers locaux :

```sh
git pull --ff-only
docker compose config --quiet
docker compose build fcp
docker compose up -d --no-deps fcp
docker compose ps fcp
```

Si Git signale des modifications locales ou une divergence, les résoudre avant
de poursuivre. Vérifier ensuite la connexion, le menu, le connecteur configuré
et les jails existantes. Ces commandes mettent à jour FCP uniquement ; elles
n’installent pas Fail2ban et ne migrent pas les planificateurs de rapports
indépendants. Actualiser le navigateur après la mise à jour. Pour une
installation native de FCP, utiliser l’environnement Python et la procédure
de service existants décrits dans [Connexion](connection.fr.md).
