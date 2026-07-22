# Détecteur de phishing pédagogique — feuille de route

## Le projet

**Le problème.** Sur WhatsApp, par SMS ou par email, les gens reçoivent en permanence des liens piégés : « votre colis est bloqué, cliquez ici », « vous avez gagné, réclamez votre cadeau », « votre compte va être suspendu ». Beaucoup cliquent sans réfléchir — souvent des personnes pas du tout techniques. Une fois le clic fait, c'est trop tard.

**La solution.** Une application web simple : on **colle le lien (et éventuellement le message qui l'accompagne) AVANT de cliquer**, et l'outil affiche :
- un **verdict clair** : dangereux / douteux / a priori sûr, avec un code couleur (rouge / orange / vert) ;
- un **score** de risque ;
- et surtout une **explication en français simple de chaque signal détecté**.

**L'angle : la pédagogie.** Les outils existants (Google Safe Browsing, VirusTotal…) donnent un verdict brut et technique, réservé aux experts. Ici, l'outil **explique** : « ce lien affiche `paypal.com` mais pointe en réalité vers un autre site », « ce domaine a été créé il y a 2 jours », « ce message crée une fausse urgence pour pousser à cliquer vite ». L'objectif n'est pas seulement de protéger l'utilisateur une fois, mais de lui **apprendre à repérer les arnaques lui-même** la prochaine fois.

**Trois domaines réunis :**
- **Développement** — l'application web (interface, serveur, affichage du résultat) et sa mise en ligne.
- **IA** — l'analyse du texte du message (ton d'urgence, fautes, demandes d'informations sensibles) via un appel d'API à un modèle.
- **Cybersécurité** — les vérifications techniques du lien (HTTPS, vrai domaine, imitation de marque, âge du domaine).

---

## Stack technique

- **Python + Flask** — le backend.
- **HTML / CSS / JavaScript** — le front.
- **Appel d'API** — pour l'analyse IA du texte.
- **Python pur** — pour les vérifications de sécurité.
- **Git + GitHub** — versionnage.
- **Hébergement gratuit** (Render ou PythonAnywhere) — pour la mise en ligne.

---

## Feuille de route (12 séances)

### Semaine 1 — Fondations

**Séance 1 — Anatomie d'un lien + environnement.** Comprendre la structure d'une URL (protocole, domaine, sous-domaine, chemin) et le piège du vrai domaine. Mettre en place l'environnement (Python, Flask, venv) et un serveur "Hello World".

**Séance 2 — Le front minimal.** Une page avec un champ de saisie et un bouton, qui envoie le lien au serveur.

**Séance 3 — La boucle complète.** Le serveur reçoit le lien et renvoie un résultat affiché à l'écran (résultat provisoire pour valider le circuit de bout en bout).

### Semaine 2 — Sécurité (le cœur du projet)

**Séance 4 — Décortiquer l'URL.** Extraire le vrai domaine, repérer l'absence de HTTPS, détecter un lien qui affiche un texte mais pointe ailleurs.

**Séance 5 — Le typosquatting.** Détecter les domaines qui imitent une marque connue (`paypa1.com`, `g00gle.com`, `whatsapp-secure.com`).

**Séance 6 — Âge et réputation du domaine.** Interroger la date de création d'un domaine (WHOIS) et produire un premier score de sécurité réel.

### Semaine 3 — IA + pédagogie

**Séance 7 — Première API.** Comprendre les APIs et appeler un modèle d'IA depuis le code.

**Séance 8 — Analyse du message.** Écrire un prompt pour détecter les marqueurs psychologiques du phishing (urgence, fautes, demandes sensibles).

**Séance 9 — Fusion + explication.** Combiner les signaux de sécurité et l'analyse IA en un score global, et générer les explications pédagogiques en français simple.

### Semaine 4 — Finition + mise en valeur

**Séance 10 — Interface.** Rendre le résultat clair et lisible pour un non-technicien (couleurs, mise en page).

**Séance 11 — Déploiement.** Mettre l'application en ligne pour la rendre accessible via un lien public.

**Séance 12 — Vitrine.** README complet (problème, solution, apprentissages, démo) et présentation du projet.

---

## Objectif d'apprentissage

Ce projet est avant tout un projet d'apprentissage : découvrir la cybersécurité (domaine nouveau pour moi) tout en consolidant mes compétences en développement web et en IA. Chaque séance associe un concept à comprendre et une brique concrète à construire.
