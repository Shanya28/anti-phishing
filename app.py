"""
app.py — Le serveur web (le "chef d'orchestre").

Il fait le lien entre :
  - la page web (templates/index.html)
  - le module sécurité (securite.py, Semaine 2)
  - le module IA (ia.py, Semaine 3)

La route /analyser reçoit le lien + le message, appelle les deux analyses,
combine leurs scores, et renvoie un résultat complet au navigateur.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from securite import analyser_securite, est_domaine_legitime
from ia import analyser_texte

app = Flask(__name__)

# FINDING 2 : limite le nombre de requetes par IP pour eviter les abus
# (surcharge du serveur, scraping des regles de detection).
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per hour"],
)


@app.route("/")
def accueil():
    return render_template("index.html")


@app.route("/analyser", methods=["POST"])
@limiter.limit("15 per minute")
def analyser():
    donnees = request.get_json()
    lien = (donnees.get("lien") or "").strip()
    message = (donnees.get("message") or "").strip()
    analyser_page = bool(donnees.get("analyser_page", False))

    # --- validation de l'entrée (principe de sécurité : ne jamais faire confiance) ---
    if not lien and not message:
        return jsonify({"erreur": "Colle un lien ou un message à analyser."}), 400

    raisons = []
    domaine = None
    score_secu = 0
    score_ia = 0

    # --- analyse SÉCURITÉ du lien (Semaine 2) ---
    if lien:
        resu_secu = analyser_securite(lien, analyser_page=analyser_page)
        score_secu = resu_secu["score"]
        domaine = resu_secu["domaine"]
        raisons += resu_secu["raisons"]

    # --- analyse IA du message (Semaine 3) ---
    if message:
        resu_ia = analyser_texte(message)
        score_ia = resu_ia["score"]
        raisons += resu_ia["raisons"]

    # --- COMBINAISON du score (pondération raisonnée) ---
    # On prend le plus fort des deux signaux comme base (un lien tres dangereux
    # OU un message tres dangereux suffit a alerter), plus une fraction de l'autre
    # (quand les deux sont suspects, on est encore plus sur). Ca evite a la fois
    # la sous-note (signal fort noye) et la sur-note (petits signaux qui s'empilent).
    base = max(score_secu, score_ia)
    autre = min(score_secu, score_ia)
    score = min(int(base + autre * 0.4), 100)

    # FINDING 3 : le score de securite du lien est un PLANCHER. Un lien
    # techniquement suspect reste au moins aussi suspect, quel que soit le
    # message (un message rassurant ne peut pas "blanchir" un lien dangereux).
    score = max(score, score_secu)

    # FINDING 4 : si le lien est un domaine legitime connu, le message seul ne
    # doit pas le faire passer "dangereux" (eviter que google.com + "clique vite"
    # soit marque dangereux, ce qui detruirait la confiance de l'utilisateur).
    if lien and est_domaine_legitime(lien):
        score = min(score, 40)

    # --- verdict global ---
    if score >= 60:
        verdict = "dangereux"
    elif score >= 25:
        verdict = "douteux"
    else:
        verdict = "sûr"

    return jsonify({
        "score": score,
        "verdict": verdict,
        "domaine": domaine,
        "raisons": raisons,
    })




@app.route("/sw.js")
def service_worker():
    """Sert le service worker depuis la racine (requis pour la PWA)."""
    return send_from_directory(".", "sw.js", mimetype="application/javascript")


if __name__ == "__main__":
    app.run(debug=True)
