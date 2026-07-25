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

## Limites connues (et honnêtes)

Ce projet est un **prototype pédagogique**, pas un service de sécurité
professionnel. Aucun détecteur de phishing n'est infaillible, celui-ci non plus :

- la liste des marques et des TLD est limitée et codée en dur ;
- l'outil ne visite pas le lien et ne suit pas les vraies redirections réseau ;
- il n'interroge pas de base de menaces en temps réel (Google Safe Browsing, PhishTank) ;
- l'affichage du « domaine » pour une adresse IP est imparfait ;
- les scores sont attribués à la main, sans base statistique.

Un résultat « sûr » ne garantit donc jamais qu'un lien est sans danger.

## Pistes d'amélioration

- interroger Google Safe Browsing / PhishTank (bases de menaces réelles) ;
- suivre les redirections et résoudre les liens raccourcis (bit.ly…) ;
- constituer un jeu de test (liens sains + phishing connus) et **mesurer** le taux de détection ;
- enrichir la détection homographe et le typosquatting.

---

Projet réalisé dans une démarche d'apprentissage : découverte de la
cybersécurité, consolidation du développement web et de l'IA.
