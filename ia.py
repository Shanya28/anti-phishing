"""
ia.py — Le cerveau "IA" du détecteur (SEMAINE 3 de ta feuille de route).

Rôle : analyser le TEXTE du message (pas le lien) pour repérer les marqueurs
psychologiques du phishing : fausse urgence, menace, demande d'infos sensibles.

IMPORTANT : cette partie a besoin d'une CLÉ D'API d'un fournisseur de modèle.
- Si tu as mis ta clé dans la variable d'environnement OPENAI_API_KEY,
  l'analyse par IA s'active automatiquement.
- Si tu n'as PAS de clé, le code bascule sur une analyse "de secours" par
  mots-clés, pour que ton app FONCTIONNE QUAND MÊME pour ta démo.

=> Tu peux donc livrer sans clé, puis brancher l'IA plus tard (Séances 7-8-9).
"""

import os

CLE_API = os.environ.get("OPENAI_API_KEY")


def analyser_texte_par_mots_cles(texte):
    """Analyse de SECOURS (sans IA) : cherche des mots typiques du phishing.
    Simple mais efficace pour une démo, et 100% gratuit / sans clé."""
    texte_bas = (texte or "").lower()
    raisons = []
    score = 0

    urgence = ["urgent", "immédiat", "immediatement", "24h", "48h", "bloqué",
               "bloque", "suspendu", "expire", "dernier avertissement", "vite"]
    menace = ["compte", "suspendu", "fermé", "ferme", "poursuite", "amende",
              "sanction", "perdre"]
    sensible = ["mot de passe", "carte", "code", "iban", "identifiant",
                "numéro de sécurité", "cvv", "pin", "connectez-vous", "cliquez"]
    appat = ["gagné", "gagne", "gratuit", "cadeau", "félicitations",
             "felicitations", "remboursement", "colis"]

    if any(m in texte_bas for m in urgence):
        score += 25
        raisons.append("Le message crée un sentiment d'urgence pour te pousser à agir vite sans réfléchir.")
    if any(m in texte_bas for m in menace):
        score += 20
        raisons.append("Le message utilise la peur (compte bloqué, sanction) pour te manipuler.")
    if any(m in texte_bas for m in sensible):
        score += 25
        raisons.append("Le message demande des informations sensibles ou un clic : un organisme sérieux ne fait jamais ça par message.")
    if any(m in texte_bas for m in appat):
        score += 20
        raisons.append("Le message fait miroiter un gain (cadeau, remboursement, colis) pour t'appâter.")

    return {"score": min(score, 100), "raisons": raisons}


def analyser_texte_par_ia(texte):
    """Analyse par IA réelle (Séances 7-8). Appelle un modèle via l'API.
    N'est utilisée que si une clé API est disponible."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=CLE_API)

        prompt = (
            "Tu es un expert en cybersécurité. Analyse ce message reçu par "
            "quelqu'un et dis s'il présente des signes de phishing (arnaque). "
            "Réponds UNIQUEMENT avec un JSON de la forme : "
            '{"score": <0-100>, "raisons": ["explication simple", ...]}. '
            "Les explications doivent être en français simple, compréhensibles "
            "par une personne non technique.\n\nMessage :\n" + texte
        )

        reponse = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        contenu = reponse.choices[0].message.content.strip()
        # on nettoie d'éventuels ```json ... ```
        contenu = contenu.replace("```json", "").replace("```", "").strip()
        import json
        data = json.loads(contenu)
        return {"score": min(int(data.get("score", 0)), 100),
                "raisons": data.get("raisons", [])}
    except Exception:
        # en cas de souci (clé invalide, réseau...), on retombe sur les mots-clés
        return analyser_texte_par_mots_cles(texte)


def analyser_texte(texte):
    """Point d'entrée : utilise l'IA si une clé est là, sinon les mots-clés."""
    if not texte or not texte.strip():
        return {"score": 0, "raisons": []}
    if CLE_API:
        return analyser_texte_par_ia(texte)
    return analyser_texte_par_mots_cles(texte)
