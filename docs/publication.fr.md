# Publication GitHub

Le dépôt public est disponible sur https://github.com/woofix/fcp. Il contient
les sources, la licence Apache-2.0, les notices, la documentation d’installation
et le workflow de tests.

Avant chaque nouvelle publication :

- vérifier la liste `git ls-files`, les différences préparées et les notices ;
- ne pas ajouter `.env`, `config/`, `data/`, `state/`, `geo/`, `logs/`, les
  e-mails réels ou les sauvegardes ;
- utiliser une identité d’auteur Git adaptée à une publication publique ;
- relire les changements, créer le commit, puis pousser vers le dépôt ;
- attendre la réussite du workflow et valider une installation indépendante
  avec les jails et journaux propres à cet environnement avant une release stable.

Les modes Docker local et Fail2ban Linux natif local sont proposés dans
l’administration de l’application. Le socket Docker et le socket Fail2ban sont
des accès sensibles à réserver aux administrateurs de confiance. Les services
externes et l’administration distante demandent leur propre intégration.
