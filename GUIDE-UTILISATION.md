# Guide d'utilisation

*Comment démarrer le système, vérifier qu'il tourne, et où regarder pour voir une détection.
La reproduction détaillée des 5 scénarios est montrée dans la vidéo ; ce guide donne les
commandes de base pour lancer/vérifier le système, pas pour la refaire ici.*

---

## 1. Démarrer / arrêter / vérifier les services

```bash
# tout démarrer
sudo systemctl start elasticsearch kibana suricata syslog-ng apache2 slack-alerts

# tout arrêter
sudo systemctl stop elasticsearch kibana suricata syslog-ng apache2 slack-alerts

# vérifier que tout est actif (doit afficher "active" 6 fois)
systemctl is-active elasticsearch kibana suricata syslog-ng apache2 slack-alerts
```

Les 6 services sont réglés pour démarrer seuls au démarrage de la VM (`enable`), donc en
temps normal il n'y a rien à lancer à la main.

## 2. Vérifier que les logs remontent bien

```bash
# nombre de documents dans chaque index (doit augmenter avec le temps)
PWE="<mot de passe elastic>"
curl -s -u "elastic:$PWE" --cacert /etc/syslog-ng/http_ca.crt \
  "https://localhost:9200/_cat/indices/suricata-*,syslog-*?v"
```

## 3. Regarder les logs dans Kibana

1. Ouvrir `http://192.168.204.129:5601` dans un navigateur, se connecter avec `elastic`.
2. Menu ☰ → **Discover**.
3. En haut à gauche, choisir la vue de données : **Suricatana** (alertes Suricata),
   **Auth (SSH/sudo)** ou **Apache access**.
4. En haut à droite, régler la période (ex. « Dernières 24 heures »).
5. Dans la barre de recherche, taper un filtre, par exemple :
   - `event_type : "alert"` → uniquement les alertes de sécurité
   - `src_ip : "192.168.204.130"` → uniquement ce qui vient de la Kali
   - `alert.signature : *scan*` → alertes qui parlent de scan

## 4. Vérifier que la notification Slack fonctionne

Le script `slack_alerts.py` tourne en continu (service `slack-alerts`) et regarde les
nouvelles alertes toutes les 30 secondes. Pour suivre ce qu'il fait :

```bash
journalctl -u slack-alerts -f
```

Dès qu'une vraie intrusion est détectée par Suricata, un message apparaît dans le canal
Slack configuré, avec la gravité, la signature, la source, la cible et un lien vers Kibana.

## 5. Test rapide de bout en bout (sans attaque réelle)

Pour vérifier que toute la chaîne fonctionne sans lancer un vrai scénario d'attaque, on peut
utiliser notre règle de test (un simple `ping`) :

```bash
# depuis n'importe quelle machine du réseau (Kali, PC Windows...)
ping -c 3 192.168.204.129
```

Cette règle est volontairement **ignorée** par le robot Slack (pour ne pas spammer à chaque
ping) mais elle apparaît dans `fast.log` et dans Kibana (`alert.signature_id : 1000001`),
ce qui permet de confirmer que Suricata → syslog-ng → Elasticsearch → Kibana fonctionne.

## 6. Lancer les 5 scénarios d'intrusion

Les commandes exactes et les logs attendus pour chacun des 5 scénarios sont listés dans le
tableau ci-dessous ; les résultats observés dans Kibana et Slack sont dans `CAPTURES.md`. Leur
exécution est montrée dans la vidéo de démonstration.

| # | Scénario | Depuis la Kali |
|---|---|---|
| 1 | Scan de ports | `nmap -sS -A -T4 192.168.204.129` |
| 2 | Brute-force SSH | `hydra -l <user> -P <wordlist> ssh://192.168.204.129` |
| 3 | Injection SQL | `curl "http://192.168.204.129/?id=1' OR '1'='1"` |
| 4 | Traversée de répertoires | `curl "http://192.168.204.129/?file=../../../../etc/passwd"` |
| 5 | Déni de service (SYN flood) | `sudo hping3 -S --flood -p 80 192.168.204.129` |

Après chaque test : regarder Kibana (Discover → Suricatana → `event_type : "alert"`) et
vérifier que le message correspondant est bien arrivé dans Slack.

## 7. Nettoyer après les tests

Le scénario 5 (SYN flood) charge la VM : l'arrêter après quelques secondes avec `Ctrl+C`
sur la Kali. Rien d'autre à nettoyer : les logs restent dans Elasticsearch, c'est voulu
(ils servent de preuve pour les captures).
