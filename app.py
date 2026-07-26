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

import os
import tempfile
from securite import analyser_securite, lire_qr_code
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



@app.route("/analyser-qr", methods=["POST"])
def analyser_qr():
    """Recoit une image de QR code, en extrait le lien, puis l'analyse."""
    if "image" not in request.files:
        return jsonify({"erreur": "Aucune image envoyee."}), 400
    fichier = request.files["image"]
    # on sauvegarde temporairement l'image pour la lire
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            fichier.save(tmp.name)
            chemin = tmp.name
        liens = lire_qr_code(chemin)
        os.unlink(chemin)  # on supprime le fichier temporaire
    except Exception:
        return jsonify({"erreur": "Impossible de lire l'image."}), 400

    if not liens:
        return jsonify({"erreur": "Aucun QR code detecte dans l'image."}), 400

    lien = liens[0]
    resu = analyser_securite(lien)
    return jsonify({
        "score": resu["score"],
        "verdict": resu["verdict"],
        "domaine": resu["domaine"],
        "raisons": [f"Lien trouve dans le QR code : {lien}"] + resu["raisons"],
        "lien_qr": lien,
    })


if __name__ == "__main__":
    app.run(debug=True)
