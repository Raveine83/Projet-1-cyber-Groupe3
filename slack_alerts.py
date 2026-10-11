#!/usr/bin/env python3
"""Envoie dans Slack les alertes Suricata stockees dans Elasticsearch.

Principe : toutes les POLL_SECONDS secondes, on cherche les nouvelles alertes
(event_type = alert) dans suricata-eve-*, on les regroupe par (signature, IP source)
pour ne pas inonder le canal, et on poste un message explicatif en francais.

Les identifiants sont lus dans le fichier CREDS (jamais ecrits dans ce script).
Seule la bibliotheque standard de Python est utilisee.
"""
import json
import os
import ssl
import sys
import time
import urllib.request
from base64 import b64encode
from collections import OrderedDict
from datetime import datetime, timezone

CREDS = os.environ.get("ALERT_CREDS", "/home/cours/projet1-identifiants.txt")
ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
CA_FILE = os.environ.get("ES_CA", "/etc/syslog-ng/http_ca.crt")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://192.168.204.129:5601")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "30"))
MAX_MESSAGES_PER_CYCLE = 10
OVERLAP_SECONDS = 20  # recouvrement : un evenement peut etre indexe apres sa date
# Signatures de test a ne pas notifier (sid de notre regle ICMP de test)
IGNORED_SIDS = {int(s) for s in os.environ.get("IGNORED_SIDS", "1000001").split(",") if s}
# Evenements internes du moteur (anomalies de flux TCP, decodage...) : pas des intrusions
IGNORED_PREFIXES = ("SURICATA ",)

# Explications pour l'administrateur selon la categorie Suricata
CONSEILS = {
    "Attempted Information Leak": "Reconnaissance : l'attaquant cherche des informations sur le systeme (scan, enumeration).",
    "Web Application Attack": "Attaque web : tentative d'exploitation du site (injection SQL, traversee de repertoires...).",
    "Attempted Administrator Privilege Gain": "Tentative d'obtenir les droits administrateur sur la machine.",
    "Attempted User Privilege Gain": "Tentative d'obtenir des droits utilisateur sur la machine.",
    "Attempted Denial of Service": "Deni de service : tentative de saturer ou de rendre un service indisponible.",
    "Potentially Bad Traffic": "Trafic suspect a analyser dans Kibana.",
    "Misc Attack": "Attaque diverse detectee : verifier la source et les cibles dans Kibana.",
}
CONSEIL_DEFAUT = "Verifier la source et la cible de l'alerte dans Kibana, puis bloquer l'IP source si elle est malveillante."
SEVERITE = {1: ":red_circle: CRITIQUE", 2: ":large_orange_circle: ELEVEE", 3: ":large_yellow_circle: MOYENNE"}


def lire_cred(prefixe):
    with open(CREDS, encoding="utf-8") as f:
        for ligne in f:
            if ligne.startswith(prefixe):
                return ligne.split(" : ", 1)[1].strip()
    sys.exit(f"Identifiant introuvable dans {CREDS} : {prefixe}")


ES_USER = "alert_notifier"
ES_PASSWORD = lire_cred("Utilisateur alert_notifier")
WEBHOOK = lire_cred("Slack webhook")
SSL_CTX = ssl.create_default_context(cafile=CA_FILE)
AUTH = "Basic " + b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()


def es_search(body):
    req = urllib.request.Request(
        f"{ES_URL}/suricata-eve-*/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": AUTH},
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=20) as r:
        return json.load(r)


def slack(texte):
    req = urllib.request.Request(
        WEBHOOK,
        data=json.dumps({"text": texte}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")


def nouvelles_alertes(depuis_ms, deja_vus):
    corps = {
        "size": 500,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"term": {"event_type.keyword": "alert"}},
            {"range": {"timestamp": {"gt": depuis_ms - OVERLAP_SECONDS * 1000, "format": "epoch_millis"}}},
        ]}},
    }
    hits = es_search(corps)["hits"]["hits"]
    return [h for h in hits if h["_id"] not in deja_vus]


def formater(groupe):
    alerte, nb, premiere, derniere = groupe["alerte"], groupe["nb"], groupe["premiere"], groupe["derniere"]
    a = alerte["alert"]
    sev = SEVERITE.get(a.get("severity"), ":white_circle: INFO")
    conseil = CONSEILS.get(a.get("category"), CONSEIL_DEFAUT)
    cible = f"{alerte.get('dest_ip', '?')}" + (f":{alerte['dest_port']}" if "dest_port" in alerte else "")
    source = f"{alerte.get('src_ip', '?')}" + (f":{alerte['src_port']}" if "src_port" in alerte else "")
    return (
        f":rotating_light: *Intrusion detectee* - {sev}\n"
        f"*Signature :* {a.get('signature')} (sid {a.get('signature_id')})\n"
        f"*Categorie :* {a.get('category')}\n"
        f"*Source -> Cible :* `{source}` -> `{cible}` ({alerte.get('proto')})\n"
        f"*Occurrences :* {nb} (de {premiere.strftime('%H:%M:%S')} a {derniere.strftime('%H:%M:%S')}, heure de la VM)\n"
        f"*Explication :* {conseil}\n"
        f"*A faire :* ouvrir Kibana ({KIBANA_URL}/app/discover) et filtrer `event_type : \"alert\"` "
        f"avec `src_ip : {alerte.get('src_ip')}` pour voir le detail."
    )


def cycle(depuis_ms, deja_vus):
    hits = nouvelles_alertes(depuis_ms, deja_vus)
    groupes = OrderedDict()
    dernier_ms = depuis_ms
    for h in hits:
        deja_vus[h["_id"]] = True
        src = h["_source"]
        dernier_ms = max(dernier_ms, int(parse_ts(src["timestamp"]).timestamp() * 1000))
        sid = src["alert"].get("signature_id")
        if sid in IGNORED_SIDS or src["alert"].get("signature", "").startswith(IGNORED_PREFIXES):
            continue
        cle = (sid, src.get("src_ip"))
        ts = parse_ts(src["timestamp"])
        if cle not in groupes:
            groupes[cle] = {"alerte": src, "nb": 0, "premiere": ts, "derniere": ts}
        groupes[cle]["nb"] += 1
        groupes[cle]["derniere"] = ts
    envoyes = 0
    for g in groupes.values():
        if envoyes >= MAX_MESSAGES_PER_CYCLE:
            slack(f":warning: {len(groupes) - envoyes} autre(s) groupe(s) d'alertes non detaille(s) ce cycle : voir Kibana.")
            break
        slack(formater(g))
        envoyes += 1
    # on ne garde en memoire que les derniers identifiants vus
    while len(deja_vus) > 5000:
        deja_vus.popitem(last=False)
    return dernier_ms, len(hits), envoyes


def main():
    deja_vus = OrderedDict()
    depuis_ms = int(time.time() * 1000)  # on ne notifie que ce qui arrive apres le demarrage
    print(f"[{datetime.now():%H:%M:%S}] notifier demarre, surveillance des alertes Suricata", flush=True)
    while True:
        try:
            depuis_ms, nb, envoyes = cycle(depuis_ms, deja_vus)
            if nb:
                print(f"[{datetime.now():%H:%M:%S}] {nb} alerte(s) lue(s), {envoyes} message(s) Slack", flush=True)
        except Exception as e:  # on ne s'arrete jamais : on reessaie au cycle suivant
            print(f"[{datetime.now():%H:%M:%S}] erreur : {e}", file=sys.stderr, flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
