# Validation de la préparation portable — 10 octobre 2026

## Contrôles réalisés

- 11 tests hors réseau réussis sur macOS/Python 3.9 pour les modules applicatifs,
  puis sur Linux/Python 3.12 dans l’image complète.
- Construction réussie de l’image Python 3.12 Alpine avec les dépendances
  déclarées dans `requirements.txt`.
- Configuration Docker Compose validée après une installation neuve.
- Démarrage réel de Gunicorn dans un conteneur jetable, sans réseau externe,
  sans socket Docker et sans port publié.
- HTTP anonyme refusé (401) ; accès authentifié à `/`, `/manage` et
  `/geo/status` réussi (200).
- Connexion à une instance Fail2ban jetable séparée de l’installation active,
  avec un nom de conteneur différent et une jail `fcp-test` sans action de
  pare-feu : lecture de l’état et de l’inventaire, lecture du fichier, validation
  de configuration et API de la carte réussies.
- Les conteneurs de validation ont été supprimés après les tests.

Les tests de collecte vérifient notamment les ports SSH personnalisés,
l’absence de journaux HTTP/SFTP facultatifs, les limites de prélèvement,
la suppression des données privées, la pièce jointe et son empreinte,
la classification d’une jail SSH personnalisée et le blocage des renvois
après soumission incertaine.

Les tests d’installation vérifient que le mot de passe reste privé et que
relancer l’installateur n’écrase pas les fichiers existants. Les tests de
configuration vérifient les réglages désactivés, la validation des adresses,
les conflits de révision et les protections d’accès à l’API.

## Limites

Les essais Docker ont été exécutés dans des instances séparées sur le même
hôte Linux. Il ne s’agit pas encore d’une validation sur plusieurs machines,
distributions ou architectures.

Aucun message réel ni signalement AbuseIPDB n’a été envoyé, aucun bannissement
ou débannissement n’a été déclenché. Les envois doivent être vérifiés avec le
relais, les sources de preuves et les destinataires de la nouvelle installation.

Le workflow GitHub est préparé, mais n’a pas encore été exécuté sur GitHub.
Le support vise Docker et l’organisation de configuration crazymax/fail2ban.
Fail2ban natif, Docker distant, authentification multi-utilisateur et
notification automatique par webhook ne sont pas implémentés.
