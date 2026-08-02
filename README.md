# 🛡️ Détecteur de phishing pédagogique

Un outil web où l'on colle un lien (et le message reçu) **avant de cliquer**.
Il donne un verdict clair, un score de risque, et surtout **explique en français
simple pourquoi** un lien ou un message est suspect — pour apprendre à repérer
les arnaques soi-même.

> Sur WhatsApp, par SMS ou par email, beaucoup de gens cliquent sur des liens
> piégés sans savoir. Cet outil analyse le lien avant le clic et explique le danger.

## Ce que l'outil détecte

**Analyse du lien (cybersécurité) :**
- absence de HTTPS ;
- sous-domaine trompeur (`paypal.arnaque.com` → le vrai site est `arnaque.com`) ;
- typosquatting : domaine imitant une marque connue (`paypa1.com` vs `paypal`) ;
- domaine récemment créé (via WHOIS).

**Analyse du message (IA) :**
- fausse urgence, menace, appât, demande d'informations sensibles.
  Utilise un modèle via API si une clé est fournie, sinon une analyse
  par mots-clés (l'app fonctionne dans les deux cas).

## Lancer le projet en local

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Puis ouvrir http://127.0.0.1:5000

## Activer l'analyse par IA (optionnel)

Définir une clé d'API avant de lancer l'app :

```bash
export OPENAI_API_KEY="ta-cle"
python app.py
```

Sans clé, l'app bascule automatiquement sur l'analyse par mots-clés.

## Structure

- `app.py` — le serveur Flask (chef d'orchestre)
- `securite.py` — les vérifications de sécurité du lien
- `ia.py` — l'analyse du texte du message
- `templates/index.html` — l'interface

## Stack

Python · Flask · HTML/CSS/JS · WHOIS · (API d'un modèle d'IA en option)

## Ce que l'outil détecte (analyse du lien)

- absence de HTTPS
- sous-domaine trompeur (`paypal.arnaque.com`)
- typosquatting, y compris chiffres imitant des lettres (`paypa1`)
- arobase trompeuse (`paypal.com@arnaque.ru`)
- redirection cachée dans les paramètres (open redirect), même encodée
- caractères homographes (ex : « а » cyrillique)
- adresse IP brute au lieu d'un nom de domaine
- empilement de sous-domaines
- extensions (TLD) statistiquement à risque
- domaine récemment créé (WHOIS)


## Données d'entraînement

Le modèle est entraîné sur le **Phishing Email Dataset** de Naser Abdullah Alam,
disponible sur Kaggle :
https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset

Ce corpus agrège sept jeux de données de recherche (Enron, Ling, CEAS, Nazario,
Nigerian Fraud, SpamAssassin), soit environ 164 000 messages étiquetés après
fusion et déduplication, répartis en 52 % de phishing et 48 % de messages
légitimes. Tous sont en anglais.

Licence : CC BY-SA 4.0.

### Performances mesurées

Évaluation sur un jeu de test séparé de 32 841 messages (20 %, stratifié) :

| Métrique | Classe phishing |
|---|---|
| Précision | 0,989 |
| Rappel | 0,991 |
| F1-score | 0,990 |
| Exactitude globale | 0,990 |

Ces chiffres valent pour des courriels anglophones comparables à ceux du corpus
d'entraînement. Sur des messages d'un style ou d'une langue différents, la
performance serait moindre.

## Limites connues (et honnêtes)

### La limite fondamentale : le lien, pas la véracité

Cet outil vérifie si un **lien** est techniquement suspect. Il ne vérifie **pas**
si l'information véhiculée est vraie.

Un site parfaitement légitime sur le plan technique (vrai domaine, HTTPS valide,
domaine ancien, aucun signal d'alerte) peut parfaitement héberger une escroquerie :
faux placement financier, fausse cagnotte, fausse promesse de gain, arnaque
sentimentale. Dans ce cas, l'outil affichera « rien à signaler », et il aura
raison sur ce qu'il mesure : le lien n'est pas piégé. La personne peut pourtant
se faire escroquer.

Vérifier la véracité d'une information relève de la vérification des faits, un
problème d'une tout autre nature, qu'aucun outil ne résout de façon fiable
aujourd'hui. Ce projet ne prétend pas s'y attaquer.

### Les autres limites

- la liste des marques et des extensions à risque est limitée et codée en dur ;
- aucune base de menaces en temps réel n'est interrogée (Google Safe Browsing, PhishTank) ;
- le modèle de classification est entraîné sur des corpus anglophones : il ne
  s'exprime que sur l'anglais, les autres langues reposent sur des règles ;
- les seuils et pondérations du score sont ajustés manuellement, sans optimisation ;
- le phishing hors lien (appels frauduleux, pièces jointes) n'est pas couvert ;
- seules les techniques connues sont détectées : une méthode nouvelle passera.

Un résultat « sûr » ne garantit donc jamais qu'un lien est sans danger.

## Pistes d'amélioration

- interroger Google Safe Browsing / PhishTank (bases de menaces réelles) ;
- suivre les redirections et résoudre les liens raccourcis (bit.ly…) ;
- constituer un jeu de test (liens sains + phishing connus) et **mesurer** le taux de détection ;
- enrichir la détection homographe et le typosquatting.

---

Projet réalisé dans une démarche d'apprentissage : découverte de la
cybersécurité, consolidation du développement web et de l'IA.
