# NET·CONTROL — Supervision et sécurité des réseaux

Projet académique de supervision réseau en **Python / Flask**, destiné à un laboratoire **Kali Linux** isolé. Capture du trafic via Scapy, alertes ARP et inondation, tableau de bord et listes de contrôle. Les règles `iptables` concernent le trafic INPUT de l’hôte exécutant l’application ; le logiciel n’est pas un pare-feu de passerelle.

## Fonctionnalités
- Surveillance du trafic et statistiques de capture (Scapy)
- Alertes sur modification IP→MAC (réponses ARP) et volume de paquets par IP dans une fenêtre glissante
- Listes blanche et noire, avec blocage `iptables` si disponible et autorisé
- Interface Flask avec authentification, journal des événements et rafraîchissement périodique
- Comptes administrateurs avec mots de passe hachés et salés (PBKDF2)

## Installation dans une VM Kali (réseau de laboratoire uniquement)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json
ip -br address                   # repérer l’interface de la VM
```

Adapter `config.json` à l’interface locale et au sous-réseau de test. Pour exécuter avec les privilèges nécessaires à Scapy/iptables, l’environnement doit être transmis au processus lancé avec `sudo` :

```bash
# Exemple : valeurs uniquement dans l'environnement local, jamais dans Git
read -rsp 'Mot de passe administrateur initial : ' ADMIN_PASS; echo
export NETCONTROL_ADMIN_USER='admin'
export NETCONTROL_ADMIN_PASSWORD="$ADMIN_PASS"
export NETCONTROL_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
unset ADMIN_PASS
sudo --preserve-env=NETCONTROL_ADMIN_USER,NETCONTROL_ADMIN_PASSWORD,NETCONTROL_SECRET_KEY   .venv/bin/python app.py
```

Le mot de passe initial (au moins 12 caractères) est nécessaire **uniquement au premier démarrage**, lorsque `admins.json` n’existe pas. Pour les démarrages ultérieurs, seul `NETCONTROL_SECRET_KEY` est requis. **Conservez une valeur de clé stable entre les redémarrages** pour préserver les sessions ; pour une VM de démonstration, les sessions peuvent être renouvelées. N’utilisez pas le projet sur un réseau tiers.

Ouvrir `http://127.0.0.1:5000` dans la VM. L’application utilise HTTP local, pas HTTPS : **ne l’exposez pas sur Internet**.

## Organisation

```text
app.py                    Routes Flask et sessions
core/sniffer.py           Scapy, détecteurs, statistiques
core/access_control.py    Listes et règles INPUT iptables
core/admins.py            Comptes / PBKDF2
core/alerts.py            Journal d’événements
templates/                Pages Jinja2
static/style.css          Interface
config.example.json       Paramètres d'exemple (à copier localement)
```

`config.json`, `admins.json`, les journaux et les fichiers `.env` sont exclus de Git.

## Vérification sans trafic réel

```bash
python3 -m unittest discover -s tests -v
```

Les tests Python isolés ne valident pas la capture réelle Scapy, la disponibilité de l’interface réseau ni les changements effectifs de pare-feu. Ces points doivent être vérifiés dans une VM Kali dédiée et autorisée.


## 🎓 Présentation académique — Tech Workshop 2026

Le **20 juin 2026**, j'ai eu l'occasion de présenter mon projet **NET·CONTROL — Supervision et sécurité des réseaux** lors du **Tech Workshop: Artificial Intelligence & Cybersecurity**, organisé à la Faculté des Sciences d'El Jadida, Université Chouaïb Doukkali.

J'ai réalisé une **démonstration pratique de l'application** devant mes collègues, mes enseignants et des responsables de l'établissement.

Cette expérience m'a permis de présenter les fonctionnalités de NET·CONTROL, d'expliquer son fonctionnement technique et de développer mes compétences en communication scientifique et technique.

**Informations sur l'événement :**
- **Date :** 20 juin 2026
- **Lieu :** AU Hall & CED — Faculté des Sciences d'El Jadida, Maroc
- **Thématiques :** Cybersécurité, intelligence artificielle et science des données

🔗 [Annonce officielle du Tech Workshop](https://www.fs.ucd.ac.ma/tech-workshop-artificial-intelligence-cybersecurity/)
![Affiche officielle du Tech Workshop 2026](tech-workshop-2026.jpg)

---

## Limitations
- Détecteurs fondés sur des règles simples (changement IP/MAC, seuil fixe) : alertes possibles sur trafic légitime
- Les règles `iptables` ajoutées dans `INPUT` ne remplacent pas un pare-feu réseau de passerelle
- Le mode HTTP local ne convient pas à une exposition externe ; utiliser HTTPS et des contrôles d’accès réseau avant tout déploiement
- La capture peut nécessiter des privilèges élevés et une interface Linux valide

Usage exclusivement pédagogique et sur des réseaux que vous êtes autorisé à administrer.
