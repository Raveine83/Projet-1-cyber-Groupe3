# Analyse et conclusion

## 1. Ce que le projet a montré

La chaîne complète fonctionne de bout en bout : un événement réseau (attaque ou simple
comportement suspect) est capté par Suricata, transporté par syslog-ng, stocké dans
Elasticsearch, consultable dans Kibana, et signalé en quelques secondes dans Slack. Ça a
été vérifié non seulement avec des tests volontaires (règle ICMP, scénarios d'attaque),
mais aussi avec un événement réel et non prévu : le démarrage de la VM Kali a généré une
alerte (`ET INFO Possible Kali Linux hostname in DHCP Request Packet`) qui est arrivée
jusqu'à Slack sans aucune intervention manuelle. Ça prouve que le système détecte aussi
ce qu'on n'a pas explicitement testé.

## 2. Limites du projet

- **Beaucoup d'alertes parasites.** Les événements `SURICATA STREAM ...` (anomalies de
  suivi de connexion dues à la carte réseau virtuelle, pas de vraies attaques) représentent
  la majorité du volume stocké. On les filtre avant Slack, mais ils continuent à remplir
  Elasticsearch inutilement.

  ![Kibana, Discover, vue Suricatana : toutes les alertes Suricata sur les 7 derniers jours](captures/01-vue-ensemble-alertes.png)
  
  *Capture 1 : Kibana, Discover, vue Suricatana : toutes les alertes Suricata sur les 7 derniers jours.*
- **IDS, pas IPS.** Suricata est en écoute passive (`af-packet`) : il détecte mais ne bloque
  rien. Pour bloquer automatiquement une IP attaquante, il faudrait le mettre en coupure
  (mode inline, `NFQUEUE`) ou le relier à un pare-feu (ex. script qui ajoute une règle
  `iptables` quand une alerte critique arrive).
- **Un seul point de panne.** Tout (IDS, collecte, stockage, visualisation, notification)
  tourne sur une seule VM. Si elle tombe, plus aucune détection. En conditions réelles, on
  séparerait au moins le stockage (Elasticsearch) du capteur (Suricata).
- **Pas de rotation des données.** Les index Elasticsearch grossissent chaque jour sans
  limite ; sans politique de cycle de vie (ILM), le disque finira par se remplir.
- **Un seul canal de notification.** Seul Slack est branché. Pas de secours si Slack est
  indisponible (pas d'e-mail ou de SMS de repli, pourtant demandés dans le sujet comme
  alternative).
- **Règles génériques.** Les règles utilisées viennent surtout du jeu ET Open ; certains
  scénarios (brute-force SSH, SYN flood) ont demandé d'écrire des règles maison ou de
  s'appuyer sur `auth.log` plutôt que sur Suricata seul, ce qui montre qu'un IDS réseau ne
  couvre pas tout : il faut aussi les journaux applicatifs.
- **Mots de passe en clair dans un fichier local.** Acceptable pour un projet de classe,
  à proscrire en production (utiliser un coffre-fort de secrets type Vault).

## 3. Améliorations possibles

- Désactiver les offloads réseau (`ethtool -K ens33 gro off lro off`) ou les règles de
  flux concernées pour supprimer le bruit `SURICATA STREAM` à la source.
- Ajouter une politique ILM sur les index (ex. suppression après 30 jours) pour maîtriser
  l'espace disque.
- Ajouter un deuxième canal de notification (e-mail via `smtplib`, déjà dans la bibliothèque
  standard Python) pour ne pas dépendre uniquement de Slack.
- Construire le dashboard Kibana personnalisé (alertes dans le temps, top IP sources, top
  signatures, répartition des codes HTTP) pour avoir une vue d'ensemble sans repasser par
  Discover. C'est fait : voir le dashboard « Sauron » ci-dessous.

  ![Dashboard Kibana « Sauron » : alertes dans le temps, signatures et IP sources, top des IP sources, codes HTTP Apache](captures/09-dashboard-personnalise.png)
  
  *Capture 9 : dashboard « Sauron », construit : alertes dans le temps, signatures avec IP source, top des IP sources et codes HTTP d'Apache.*
- Ajouter une réaction automatique simple : un script qui, en recevant une alerte critique
  répétée depuis une même IP, l'ajoute à une liste de blocage (`iptables` ou `fail2ban`).
- Dupliquer Elasticsearch sur un second nœud pour sortir du statut `yellow` (actuellement
  un seul nœud = pas de réplique possible), et séparer le capteur IDS du serveur de stockage
  sur deux machines distinctes.

## 4. Perspectives et veille technologique

Ce projet couvre la détection réseau (IDS) et la centralisation de logs (SIEM minimal).
Pour aller plus loin, plusieurs pistes existent dans l'écosystème actuel de la sécurité :

- **Wazuh** : agent de sécurité qui ajoute la détection côté hôte (EDR léger) — intégrité
  de fichiers, détection de rootkits, conformité — et sait aussi recevoir les alertes
  Suricata. C'est l'outil « en plus » proposé en bonus par le sujet.
- **SOAR (Security Orchestration, Automation and Response)** : des outils comme TheHive +
  Cortex ou Shuffle permettent d'aller au-delà de la simple notification et de déclencher
  automatiquement une réponse (bloquer une IP, ouvrir un ticket, isoler une machine) quand
  une alerte critique arrive — la suite logique de notre robot Slack.
- **Détection comportementale / machine learning** : Elastic propose des fonctions de
  détection d'anomalies par apprentissage automatique (ML jobs) qui repèrent des écarts de
  comportement sans règle écrite à l'avance, utile contre des attaques inédites que les
  signatures ET Open ne connaissent pas encore.
- **Zeek** : alternative/complément à Suricata, plus orienté analyse de protocole en
  profondeur et scripts d'investigation, souvent utilisé en complément d'un IDS à
  signatures plutôt qu'à sa place.
- **Threat Intelligence** : enrichir les alertes avec des listes d'IP malveillantes connues
  (flux de type MISP ou AbuseIPDB) pour prioriser automatiquement les vraies menaces parmi
  le volume d'alertes.
- **Conteneurisation** : faire tourner chaque brique (Suricata, Elasticsearch, Kibana,
  syslog-ng) dans des conteneurs Docker séparés faciliterait la mise à l'échelle et la
  portabilité du projet sur une autre machine.

En résumé, ce projet pose les fondations (capter, transporter, stocker, visualiser,
notifier) ; les évolutions naturelles vont vers plus d'automatisation de la réponse
(SOAR), plus d'intelligence dans la détection (ML, threat intel), et plus de robustesse
de l'architecture (plusieurs nœuds, conteneurs, rotation des données).
