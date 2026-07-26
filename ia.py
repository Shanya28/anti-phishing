# -*- coding: utf-8 -*-
"""
ia.py — Le cerveau "IA" du detecteur (SEMAINE 3 de ta feuille de route).

VERSION AMELIOREE (etape 1/2 de l'evolution IA) :
  - analyse par mots-cles PLUS MALIGNE : combinaisons de signaux, demandes
    d'argent, salutations generiques, coordonnees bancaires, comptes a rebours.
  - (etape 2, plus tard : entrainer un vrai modele ML dans un fichier a part.)

Sans cle d'API : analyse par mots-cles amelioree (gratuit, ce fichier).
Avec cle d'API : vraie analyse par modele de langage (fonction analyser_texte_par_ia).
"""

import os
import re

CLE_API = os.environ.get("OPENAI_API_KEY")

# --- Chargement du modele ML (etape 2). S'il n'existe pas, on s'en passe. ---
try:
    import joblib
    _modele_ml = joblib.load("modele_phishing.joblib")
    _vectoriseur_ml = joblib.load("vectoriseur_phishing.joblib")
    MODELE_ML_DISPONIBLE = True
except Exception:
    MODELE_ML_DISPONIBLE = False


# Mots tres frequents en francais : servent a deviner la langue du message.
_MOTS_FR = ["le", "la", "les", "de", "des", "un", "une", "et", "est", "vous",
            "votre", "vos", "tu", "ton", "ta", "je", "pour", "avec", "sur",
            "ce", "cette", "qui", "que", "pas", "plus", "bonjour", "merci",
            "coucou", "salut", "soir", "matin", "demain", "aujourd"]


def _texte_probablement_francais(texte):
    """Heuristique simple : compte les mots tres courants du francais."""
    mots = set(texte.lower().split())
    communs = sum(1 for m in _MOTS_FR if m in mots)
    return communs >= 2


def analyser_texte_par_ml(texte):
    """Utilise le modele entraine pour predire phishing/legitime.
    IMPORTANT : le modele est anglophone. S'il recoit du francais, il devine
    mal AVEC assurance. On ne l'utilise donc PAS si le texte semble francais."""
    if not MODELE_ML_DISPONIBLE:
        return None
    if _texte_probablement_francais(texte):
        return None  # on laisse les mots-cles francais gerer
    try:
        X = _vectoriseur_ml.transform([texte])
        proba_phishing = _modele_ml.predict_proba(X)[0]
        classes = list(_modele_ml.classes_)
        idx = classes.index("phishing")
        p = proba_phishing[idx]  # probabilite que ce soit du phishing (0 a 1)
        score = int(p * 100)
        raisons = []
        if p >= 0.5:
            raisons.append(
                f"Mon modele d'intelligence artificielle estime ce message suspect "
                f"(confiance {p:.0%}), en se basant sur des milliers de mots appris."
            )
        return {"score": score, "raisons": raisons}
    except Exception:
        return None


# --- Dictionnaires de signaux, regroupes par CATEGORIE ---
SIGNAUX = {
    "urgence": {
        "poids": 20,
        "mots": ["urgent", "immediat", "immediatement", "tout de suite", "vite",
                 "rapidement", "24h", "48h", "72h", "expire", "derniere chance",
                 "dernier avertissement", "avant ce soir", "delai", "maintenant"],
        "explication": "Le message cree un sentiment d'urgence pour te pousser a agir vite sans reflechir.",
    },
    "menace": {
        "poids": 20,
        "mots": ["bloque", "suspendu", "ferme", "desactive", "supprime", "poursuite",
                 "amende", "sanction", "penalite", "perdre", "perte", "restreint",
                 "verrouille", "limite", "definitivement"],
        "explication": "Le message utilise la peur (compte bloque, sanction) pour te manipuler.",
    },
    "infos_sensibles": {
        "poids": 25,
        "mots": ["mot de passe", "identifiant", "code confidentiel", "code secret",
                 "code pin", "cvv", "code de securite", "connectez-vous", "connecte-toi",
                 "verifiez votre compte", "confirmez votre identite", "authentifi"],
        "explication": "Le message demande des informations sensibles ou de te connecter : un organisme serieux ne fait jamais ca par message.",
    },
    "argent_banque": {
        "poids": 25,
        "mots": ["carte bancaire", "numero de carte", "iban", "rib", "virement",
                 "coordonnees bancaires", "paiement", "payer", "frais", "remboursement",
                 "facture", "prelevement", "compte bancaire"],
        "explication": "Le message parle d'argent ou demande des coordonnees bancaires : signal d'alerte majeur.",
    },
    "appat": {
        "poids": 20,
        "mots": ["gagne", "gagnez", "gratuit", "cadeau", "felicitations", "recompense",
                 "tirage au sort", "vous avez ete selectionne", "offre exclusive",
                 "bon d'achat", "cheque", "heritage", "loterie", "colis en attente",
                 "vous avez recu", "reclamez", "profitez", "offert"],
        "explication": "Le message fait miroiter un gain (cadeau, argent, prix) pour t'appater.",
    },
    "colis_livraison": {
        "poids": 20,
        "mots": ["colis", "livraison", "chronopost", "colissimo", "mondial relay",
                 "frais de douane", "frais de livraison", "reexpedition", "suivi de colis",
                 "votre paquet", "point relais", "bloque en douane"],
        "explication": "Le message joue sur une fausse histoire de colis (arnaque tres courante en France) pour te faire payer des frais.",
    },
    "organisme_usurpe": {
        "poids": 15,
        "mots": ["ameli", "assurance maladie", "caf", "urssaf", "impots", "impot",
                 "dgfip", "service public", "securite sociale", "compte formation",
                 "cpf", "prime energie", "cheque energie", "amende", "antai"],
        "explication": "Le message se fait passer pour un organisme officiel francais (impots, Ameli, CAF...) : une usurpation frequente. Ces organismes ne demandent jamais tes coordonnees par message.",
    },
    "salutation_generique": {
        "poids": 10,
        "mots": ["cher client", "cher utilisateur", "cher membre", "bonjour client",
                 "madame, monsieur", "chere cliente"],
        "explication": "Le message utilise une salutation impersonnelle (« Cher client ») : une vraie entreprise connait ton nom.",
    },
}

# Combinaisons particulierement dangereuses (bonus de score)
COMBINAISONS_DANGEREUSES = [
    ("urgence", "infos_sensibles"),
    ("menace", "infos_sensibles"),
    ("urgence", "argent_banque"),
    ("appat", "argent_banque"),
]


def _nettoyer(texte):
    """Minuscule + retire les accents pour matcher malgre les variantes."""
    texte = (texte or "").lower()
    accents = {"é": "e", "è": "e", "ê": "e", "à": "a", "â": "a",
               "î": "i", "ï": "i", "ô": "o", "û": "u", "ù": "u", "ç": "c"}
    for a, b in accents.items():
        texte = texte.replace(a, b)
    return texte


def analyser_texte_par_mots_cles(texte):
    """Analyse AMELIOREE : detecte les categories de signaux, les combinaisons
    dangereuses, et quelques motifs (comptes a rebours, liens raccourcis cites)."""
    t = _nettoyer(texte)
    score = 0
    raisons = []
    categories_presentes = set()

    for nom, info in SIGNAUX.items():
        if any(mot in t for mot in info["mots"]):
            score += info["poids"]
            raisons.append(info["explication"])
            categories_presentes.add(nom)

    # Bonus : combinaisons particulierement typiques du phishing
    for a, b in COMBINAISONS_DANGEREUSES:
        if a in categories_presentes and b in categories_presentes:
            score += 15
            raisons.append(
                "Ce message combine plusieurs techniques de manipulation en meme temps "
                "(par ex. urgence + demande d'infos) : c'est un schema classique d'arnaque."
            )
            break  # un seul bonus de combinaison

    # Motif : compte a rebours (ex "sous 24h", "dans les 48 heures", "delai de 2 jours")
    # On exige un mot d'echeance (sous/dans/delai/avant/reste) pour ne PAS confondre
    # avec une simple heure de rendez-vous ("on se voit a 20h").
    if re.search(r"\b(sous|dans|delai|avant|reste|expire\w*|plus que)\b[^.]{0,15}\d{1,3}\s?(h|heures?|jours?|minutes?)\b", t):
        if "urgence" not in categories_presentes:
            score += 10
            raisons.append("Le message impose un delai chiffre pour te presser.")

    # Motif : presence de BEAUCOUP de majuscules (cri) dans le texte original
    lettres = [c for c in (texte or "") if c.isalpha()]
    if lettres and sum(c.isupper() for c in lettres) / len(lettres) > 0.5 and len(lettres) > 15:
        score += 10
        raisons.append("Le message est ecrit en grande partie en MAJUSCULES, une facon d'attirer l'attention et de presser.")

    return {"score": min(score, 100), "raisons": raisons}


def analyser_texte_par_ia(texte):
    """Vraie analyse par modele de langage (si une cle API est disponible)."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=CLE_API)
        prompt = (
            "Tu es un expert en cybersecurite. Analyse ce message et dis s'il "
            "presente des signes de phishing. Reponds UNIQUEMENT en JSON : "
            '{"score": <0-100>, "raisons": ["explication simple en francais", ...]}.'
            "\n\nMessage :\n" + texte
        )
        rep = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        )
        import json
        contenu = rep.choices[0].message.content.strip()
        contenu = contenu.replace("```json", "").replace("```", "").strip()
        data = json.loads(contenu)
        return {"score": min(int(data.get("score", 0)), 100),
                "raisons": data.get("raisons", [])}
    except Exception:
        return analyser_texte_par_mots_cles(texte)


def analyser_texte(texte):
    """Point d'entree. Ordre de preference :
       1. l'API d'un modele de langage (si cle presente) = le plus puissant
       2. notre modele ML entraine (si disponible)
       3. les mots-cles ameliores (toujours dispo, filet de securite)
    On COMBINE le ML et les mots-cles pour plus de robustesse."""
    if not texte or not texte.strip():
        return {"score": 0, "raisons": []}

    if CLE_API:
        return analyser_texte_par_ia(texte)

    # analyse par mots-cles (toujours)
    res_mots = analyser_texte_par_mots_cles(texte)

    # on ajoute l'avis du modele ML s'il est la
    res_ml = analyser_texte_par_ml(texte)
    if res_ml:
        # STRATEGIE : on prend le MAXIMUM des deux signaux plutot qu'une moyenne.
        # Raison : le modele ML est fort en anglais, les mots-cles couvrent le
        # francais. Un fort signal de l'un ne doit pas etre dilue par l'autre qui
        # ne "parle pas la langue". On garde donc le plus alarmant des deux, avec
        # un petit bonus quand les DEUX s'accordent (plus de certitude).
        base = max(res_ml["score"], res_mots["score"])
        accord = min(res_ml["score"], res_mots["score"])
        score = base + int(accord * 0.15)  # bonus si les deux detectent
        raisons = res_mots["raisons"] + res_ml["raisons"]
        return {"score": min(score, 100), "raisons": raisons}

    return res_mots
