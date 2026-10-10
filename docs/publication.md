# Préparation de la publication GitHub

Le dépôt local contient les sources, la licence Apache-2.0, les notices,
la documentation d’installation et le workflow de tests. Aucune publication
ni création de dépôt distant n’a été effectuée. Le compte et le nom du dépôt
restent à choisir.

Avant publication :

- vérifier la liste `git ls-files`, les différences préparées et les notices ;
- ne pas ajouter `.env`, `config/`, `data/`, `state/`, `geo/`, `logs/`, les
  e-mails réels ou les sauvegardes ;
- choisir une identité d’auteur Git et créer le premier commit ;
- créer le dépôt GitHub choisi, ajouter son adresse comme `origin`, puis
  pousser `main` ;
- attendre la réussite du workflow et valider une installation indépendante
  avec les jails et journaux propres à cet environnement avant une release stable.

Cette première distribution cible Docker sur Linux avec un conteneur
Fail2ban existant. Le socket Docker reste un accès d’administration ; un
backend natif ou une connexion distante ne sont pas implémentés.
