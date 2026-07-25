"""
app.py — Le serveur web (le "chef d'orchestre").

Il fait le lien entre :
  - la page web (templates/index.html)
  - le module sécurité (securite.py, Semaine 2)
  - le module IA (ia.py, Semaine 3)

La route /analyser reçoit le lien + le message, appelle les deux analyses,
combine leurs scores, et renvoie un résultat complet au navigateur.
"""

from flask import Flask, render_template, request, jsonify

from securite import analyser_securite
from ia import analyser_texte

app = Flask(__name__)


@app.route("/")
def accueil():
    return render_template("index.html")


@app.route("/analyser", methods=["POST"])
def analyser():
    donnees = request.get_json()
    lien = (donnees.get("lien") or "").strip()
    message = (donnees.get("message") or "").strip()

    # --- validation de l'entrée (principe de sécurité : ne jamais faire confiance) ---
    if not lien and not message:
        return jsonify({"erreur": "Colle un lien ou un message à analyser."}), 400

    raisons = []
    score = 0
    domaine = None

    # --- analyse SÉCURITÉ du lien (Semaine 2) ---
    if lien:
        resu_secu = analyser_securite(lien)
        score += resu_secu["score"]
        domaine = resu_secu["domaine"]
        raisons += resu_secu["raisons"]

    # --- analyse IA du message (Semaine 3) ---
    if message:
        resu_ia = analyser_texte(message)
        score += resu_ia["score"]
        raisons += resu_ia["raisons"]

    score = min(score, 100)

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


if __name__ == "__main__":
    app.run(debug=True)
