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

from securite import analyser_securite, est_domaine_legitime, ressemble_a_un_lien, extension_impossible, est_une_adresse_ip, extraire_lien_du_texte
from ia import analyser_texte



# ---------------------------------------------------------------------------
# STATISTIQUES D'USAGE (volontairement minimalistes)
# On compte SEULEMENT le nombre d'analyses et leur repartition par verdict.
# On n'enregistre AUCUN lien, AUCUN message, AUCUNE donnee personnelle :
# ce serait sensible pour les utilisateurs et inutile pour savoir si l'outil sert.
# ---------------------------------------------------------------------------
import json as _json
import os as _os
from datetime import date as _date
from threading import Lock as _Lock

FICHIER_STATS = "statistiques.json"
_verrou_stats = _Lock()


def _charger_stats():
    try:
        with open(FICHIER_STATS, encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return {"total": 0, "par_verdict": {}, "par_jour": {}}


def enregistrer_analyse(verdict):
    """Incremente les compteurs. Le verrou evite les problemes si deux
    requetes arrivent en meme temps."""
    with _verrou_stats:
        s = _charger_stats()
        s["total"] = s.get("total", 0) + 1
        s["par_verdict"][verdict] = s["par_verdict"].get(verdict, 0) + 1
        jour = str(_date.today())
        s["par_jour"][jour] = s["par_jour"].get(jour, 0) + 1
        # on ne garde que les 30 derniers jours pour ne pas grossir indefiniment
        if len(s["par_jour"]) > 30:
            for vieux in sorted(s["par_jour"])[:-30]:
                del s["par_jour"][vieux]
        try:
            with open(FICHIER_STATS, "w", encoding="utf-8") as f:
                _json.dump(s, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # si l'ecriture echoue, on ne casse pas l'analyse


app = Flask(__name__)

# Refuse toute requete de plus de 1 Mo (protection contre les envois massifs).
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

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
    # Si le corps n'est pas du JSON valide, on repond proprement au lieu de planter.
    donnees = request.get_json(silent=True)
    if not isinstance(donnees, dict):
        return jsonify({"erreur": "Requête invalide."}), 400

    lien = (donnees.get("lien") or "").strip()
    message = (donnees.get("message") or "").strip()
    analyser_page = bool(donnees.get("analyser_page", False))

    # Limite de taille : evite qu'on sature le serveur avec un texte enorme.
    LIMITE_LIEN, LIMITE_MESSAGE = 2000, 10000
    if len(lien) > LIMITE_LIEN or len(message) > LIMITE_MESSAGE:
        return jsonify({"erreur": "Le texte envoyé est trop long. Colle seulement le lien et le message concernés."}), 400

    # --- validation de l'entrée (principe de sécurité : ne jamais faire confiance) ---
    # Le LIEN est obligatoire : c'est le role de cet outil. Analyser un message
    # seul donnerait un verdict rassurant sans avoir examine l'essentiel, ce qui
    # serait une fausse reassurance (plus dangereuse qu'une absence de reponse).
    if not lien:
        return jsonify({"erreur": "Colle le lien que tu as reçu : c'est lui que j'examine. Le message est un complément facultatif."}), 400

    # Beaucoup de gens collent le message entier plutot que le lien seul.
    # On tente d'en extraire le lien avant de refuser.
    if not ressemble_a_un_lien(lien):
        candidat = extraire_lien_du_texte(lien)
        if candidat and ressemble_a_un_lien(candidat):
            lien = candidat

    if not ressemble_a_un_lien(lien):
        # Message adapte : une extension contenant des chiffres (micr0soft) n'est
        # pas une faute de frappe de l'utilisateur, c'est un signal en soi.
        if extension_impossible(lien) and not est_une_adresse_ip(lien):
            return jsonify({"erreur": "Attention : la fin de cette adresse n'existe pas comme vraie extension de site (elle contient des chiffres). C'est souvent le signe d'une imitation. Ne clique pas dessus."}), 400
        return jsonify({"erreur": "Ça ne ressemble pas à un lien. Vérifie que tu l'as bien collé en entier (par exemple https://...)."}), 400

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

    enregistrer_analyse(verdict)

    return jsonify({
        "score": score,
        "verdict": verdict,
        "domaine": domaine,
        "raisons": raisons,
    })





@app.route("/stats")
@limiter.limit("20 per hour")
def stats():
    """Page privee pour consulter les statistiques d'usage.
    Protegee par une cle : /stats?cle=TA_CLE
    La cle se definit dans la variable d'environnement CLE_STATS.
    (On ne met JAMAIS un mot de passe en dur dans le code.)"""
    import os
    cle_attendue = os.environ.get("CLE_STATS")
    if not cle_attendue:
        return "Statistiques desactivees (variable CLE_STATS non definie).", 403
    if request.args.get("cle") != cle_attendue:
        return "Acces refuse.", 403

    s = _charger_stats()
    jours = sorted(s.get("par_jour", {}).items(), reverse=True)[:14]
    lignes = "".join(
        f"<tr><td>{j}</td><td style='text-align:right'>{n}</td></tr>"
        for j, n in jours
    )
    verdicts = "".join(
        f"<tr><td>{v}</td><td style='text-align:right'>{n}</td></tr>"
        for v, n in sorted(s.get("par_verdict", {}).items())
    )
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>Statistiques</title><style>
body{{font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;padding:0 16px;color:#2a3b47;background:#fbf7ee}}
h1{{font-size:1.4rem}} h2{{font-size:1rem;margin-top:28px;color:#b5793a}}
table{{width:100%;border-collapse:collapse;margin-top:8px}}
td{{padding:6px 4px;border-bottom:1px solid #ddd2bd;font-size:0.95rem}}
.total{{font-size:2.4rem;font-weight:700;color:#3a5f7d}}
.note{{font-size:0.82rem;color:#6b7780;margin-top:26px;line-height:1.5}}
</style></head><body>
<h1>Statistiques d'usage</h1>
<p class="total">{s.get('total', 0)}</p>
<p>analyses effectuees au total</p>
<h2>Par verdict</h2><table>{verdicts or '<tr><td>aucune donnee</td></tr>'}</table>
<h2>Par jour (14 derniers)</h2><table>{lignes or '<tr><td>aucune donnee</td></tr>'}</table>
<p class="note">Seuls des compteurs sont enregistres : aucun lien, aucun message,
aucune donnee personnelle n'est conserve. Sur l'hebergement gratuit, les compteurs
peuvent repartir a zero apres un redemarrage du serveur.</p>
</body></html>"""


@app.route("/sw.js")
def service_worker():
    """Sert le service worker depuis la racine (requis pour la PWA)."""
    return send_from_directory(".", "sw.js", mimetype="application/javascript")


if __name__ == "__main__":
    # Le mode debug expose un debogueur qui permet d'executer du code : il ne
    # doit JAMAIS etre actif en ligne. Ici il est desactive par defaut ; pour
    # l'activer en local : FLASK_DEBUG=1 python app.py
    import os
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug)
