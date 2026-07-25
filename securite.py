"""
securite.py — Le cerveau "cybersécurité" du détecteur de phishing.
VERSION AMÉLIORÉE : plusieurs failles corrigées (voir commentaires "AMÉLIORATION").

Correspond à la SEMAINE 2 de ta feuille de route + corrections avancées :
  - Séance 4 : décortiquer l'URL (vrai domaine, HTTPS)
  - Séance 5 : typosquatting (imitation de marque)
  - Séance 6 : âge du domaine (WHOIS)
  - Corrections : open redirect, caractères homographes, TLD suspects,
                  IP directe, @ dans l'URL, sous-domaines multiples.

IMPORTANT — a lire et a assumer :
Aucun detecteur de phishing n'est infaillible, celui-ci non plus. Ces
ameliorations le rendent nettement plus robuste, mais il reste un projet
pedagogique. Il ne remplace PAS un vrai service de securite, et ne doit jamais
servir a affirmer a quelqu'un qu'un lien est "sur" a 100%.
"""

from urllib.parse import urlparse, unquote
import unicodedata
import Levenshtein

try:
    import requests
    REQUESTS_DISPONIBLE = True
except Exception:
    REQUESTS_DISPONIBLE = False

try:
    from bs4 import BeautifulSoup
    BS4_DISPONIBLE = True
except Exception:
    BS4_DISPONIBLE = False

try:
    from pyzbar.pyzbar import decode as _qr_decode
    from PIL import Image as _PILImage
    QR_DISPONIBLE = True
except Exception:
    QR_DISPONIBLE = False

try:
    import whois
    WHOIS_DISPONIBLE = True
except Exception:
    WHOIS_DISPONIBLE = False


def normaliser(lien):
    lien = (lien or "").strip()
    if not lien.startswith("http://") and not lien.startswith("https://"):
        lien = "http://" + lien
    return lien


def extraire_hote(lien):
    hote = urlparse(normaliser(lien)).netloc.lower()
    if "@" in hote:
        hote = hote.split("@")[-1]
    return hote.split(":")[0]


def extraire_domaine(lien):
    hote = extraire_hote(lien)
    parties = hote.split(".")
    if len(parties) >= 2:
        return ".".join(parties[-2:])
    return hote


def utilise_https(lien):
    return (lien or "").strip().lower().startswith("https://")


MARQUES_CONNUES = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "whatsapp", "facebook", "instagram", "orange", "free", "sfr",
    "laposte", "ameli", "impots", "chronopost", "colissimo", "dhl",
    "creditagricole", "bnpparibas", "societegenerale", "boursorama",
    "leboncoin", "vinted", "spotify", "linkedin", "outlook", "gmail",
    "decathlon", "fnac", "cdiscount", "carrefour", "auchan", "edf",
    "engie", "bouygues", "caf", "urssaf", "revolut", "n26", "lcl",
    "banquepostale", "hellobank", "coinbase", "binance", "steam",
    "epicgames", "disney", "twitter", "tiktok", "snapchat", "ebay",
    "aliexpress", "wetransfer", "dropbox", "docusign", "yahoo",
]

# Domaines legitimes connus : on ne les signale JAMAIS comme suspects.
# (evite les faux positifs sur les vrais sites des marques et services connus)
DOMAINES_LEGITIMES = [
    "paypal.com", "google.com", "apple.com", "microsoft.com", "microsoftonline.com",
    "amazon.fr", "amazon.com", "netflix.com", "whatsapp.com", "facebook.com",
    "instagram.com", "laposte.fr", "ameli.fr", "impots.gouv.fr", "service-public.fr",
    "github.com", "leboncoin.fr", "vinted.fr", "spotify.com", "linkedin.com",
    "live.com", "outlook.com", "gmail.com", "wikipedia.org", "orange.fr",
]


def est_domaine_legitime(lien):
    """True si le vrai domaine fait partie de la liste blanche."""
    return extraire_domaine(lien) in DOMAINES_LEGITIMES


TLD_SUSPECTS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
                "click", "link", "zip", "review", "country", "kim", "loan",
                "men", "date", "racing", "win", "bid", "stream", "gdn",
                "mom", "party", "trade", "download", "science", "cricket",
                "rest", "buzz", "icu", "cyou", "sbs", "quest"]

# Mots souvent présents dans les URL de phishing (dans le domaine ou le chemin)
MOTS_HAMECONNAGE = ["secure", "verify", "verification", "account", "update",
                    "confirm", "login", "signin", "banking", "suspended",
                    "unlock", "recover", "validation", "customer", "webscr",
                    "securite", "verifier", "compte", "connexion", "identifiant"]


def contient_marque_deguisee(lien):
    """Detecte une marque connue presente comme MOT SEPARE dans l'hote
    (paypal.arnaque.com) mais absente du vrai domaine. On decoupe sur les
    points ET les tirets pour ne PAS confondre 'apple' dans 'applepie'."""
    hote = extraire_hote(lien)
    domaine = extraire_domaine(lien)
    nom_domaine = domaine.split(".")[0]
    # liste des "mots" de l'hote (separes par . et -)
    mots = []
    for partie in hote.split("."):
        mots.extend(partie.split("-"))
    for marque in MARQUES_CONNUES:
        # la marque doit etre un mot entier de l'hote, pas noyee dans un mot
        if marque in mots and marque != nom_domaine:
            return marque
    return None


def _normaliser_caracteres(mot):
    """Ramene les chiffres/caracteres imitant des lettres a leur equivalent.
    Ex: 'p4yp0l' -> 'paypol'. Aide a demasquer le typosquatting."""
    table = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
             "7": "t", "@": "a", "$": "s", "|": "l"}
    return "".join(table.get(c, c) for c in mot.lower())


def ressemble_a_une_marque(lien):
    """Typosquatting AFFINE : detecte les imitations de marque, y compris
    - substitutions de caracteres (paypa1, p4ypal)
    - marques noyees dans des mots composes (paypal-france-securise)
    - fautes de 1 a 2 lettres selon la longueur de la marque."""
    domaine = extraire_domaine(lien)
    nom = domaine.split(".")[0]
    # on decoupe le nom en morceaux (tirets, underscores) ET on garde le nom entier
    morceaux = nom.replace("_", "-").split("-")
    morceaux.append(nom.replace("-", ""))  # version collee

    for morceau in morceaux:
        variante = _normaliser_caracteres(morceau)
        for marque in MARQUES_CONNUES:
            # cas 1 : identique apres normalisation mais pas le vrai domaine
            if variante == marque and nom != marque:
                return marque
            # cas 2 : la marque apparait comme MORCEAU separe (paypal-securise),
            # pas noyee dans un mot normal comme "applepie". On exige que le morceau
            # courant SOIT la marque, ou qu'un mot d'hameconnage accompagne.
            if len(marque) >= 5 and marque in variante and variante != marque and nom != marque:
                autres = variante.replace(marque, "")
                # suspect seulement si le reste ressemble a du phishing (mot-cle connu)
                if any(mot in autres for mot in ["secur", "verif", "compte", "account",
                        "login", "france", "service", "client", "support", "official",
                        "confirm", "update", "connexion", "auth"]):
                    return marque
            # cas 3 : tres proche (fautes) - seuil selon longueur
            seuil = 1 if len(marque) < 6 else 2
            d = Levenshtein.distance(variante, marque)
            if 0 < d <= seuil and abs(len(variante) - len(marque)) <= seuil:
                return marque
    return None


def a_une_redirection_cachee(lien):
    lien_decode = unquote(lien or "")
    if "?" in lien_decode:
        parametres = lien_decode.split("?", 1)[1].lower()
        if "http://" in parametres or "https://" in parametres:
            return True
    return False


def a_des_caracteres_trompeurs(lien):
    hote = extraire_hote(lien)
    for c in hote:
        if c.isalpha() and not c.isascii():
            nom = unicodedata.name(c, "")
            if "CYRILLIC" in nom or "GREEK" in nom or "LATIN" not in nom:
                return True
    return False


def a_arobase_trompeur(lien):
    """L'arobase dans une URL fait que le navigateur ignore tout ce qui est AVANT
    et va sur ce qui suit. Ex: paypal.com@arnaque.ru -> va sur arnaque.ru."""
    apres_schema = normaliser(lien).split("://", 1)[-1]
    avant_chemin = apres_schema.split("/", 1)[0]
    return "@" in avant_chemin


def est_une_adresse_ip(lien):
    hote = extraire_hote(lien)
    parties = hote.split(".")
    if len(parties) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parties):
        return True
    return False


def a_trop_de_sous_domaines(lien):
    return extraire_hote(lien).count(".") >= 4


def tld_suspect(lien):
    tld = extraire_domaine(lien).split(".")[-1]
    return tld if tld in TLD_SUSPECTS else None



def resoudre_redirections(lien):
    """Suit les redirections HTTP pour trouver la VRAIE destination finale.
    Demasque les liens raccourcis (bit.ly...) et les redirections en chaine.
    Renvoie (url_finale, liste_des_etapes) ou (lien, []) si impossible."""
    if not REQUESTS_DISPONIBLE:
        return lien, []
    try:
        r = requests.head(normaliser(lien), allow_redirects=True, timeout=5,
                          headers={"User-Agent": "Mozilla/5.0"})
        etapes = [rep.url for rep in r.history]
        finale = r.url
        if finale and finale != normaliser(lien):
            return finale, etapes + [finale]
        return lien, []
    except Exception:
        return lien, []


def domaine_ou_ip(lien):
    """Comme extraire_domaine mais renvoie l'IP complete si c'en est une
    (corrige l'affichage '4.10' au lieu de '192.168.4.10')."""
    hote = extraire_hote(lien)
    if est_une_adresse_ip(lien):
        return hote
    return extraire_domaine(lien)


def contient_mots_hameconnage(lien):
    """Compte les mots typiques du phishing dans l'URL (domaine + chemin)."""
    lien_bas = unquote(lien or "").lower()
    trouves = [m for m in MOTS_HAMECONNAGE if m in lien_bas]
    return trouves


def url_trop_longue_ou_complexe(lien):
    """Une URL anormalement longue ou bourree de caracteres speciaux
    est un signal de phishing (on noie le vrai domaine)."""
    l = lien or ""
    raisons = []
    if len(l) > 100:
        raisons.append("longueur")
    # beaucoup de chiffres dans l'hote
    hote = extraire_hote(lien)
    nb_chiffres = sum(c.isdigit() for c in hote)
    if nb_chiffres >= 4 and not est_une_adresse_ip(lien):
        raisons.append("chiffres")
    # caracteres d'encodage suspects
    if l.count("%") >= 3:
        raisons.append("encodage")
    return raisons


def age_domaine_en_jours(lien):
    if not WHOIS_DISPONIBLE:
        return None
    try:
        from datetime import datetime
        infos = whois.whois(extraire_domaine(lien))
        creation = infos.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        return (datetime.now() - creation).days
    except Exception:
        return None



def analyser_contenu_page(lien):
    """Recupere la page d'arrivee et cherche des signes de faux formulaire
    de connexion (champ mot de passe + demande d'infos sensibles).
    Ne visite le site QU'UNE fois, avec timeout. Renvoie une liste de raisons."""
    if not (REQUESTS_DISPONIBLE and BS4_DISPONIBLE):
        return []
    raisons = []
    try:
        r = requests.get(normaliser(lien), timeout=5,
                         headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")

        # champ mot de passe present ?
        a_mot_de_passe = bool(soup.find("input", {"type": "password"}))
        # le domaine affiche-t-il une marque connue dans le TITRE alors que
        # le vrai domaine est autre chose ? (page qui se fait passer pour X)
        titre = (soup.title.string if soup.title and soup.title.string else "").lower()
        domaine = extraire_domaine(lien)
        marque_titre = None
        for m in MARQUES_CONNUES:
            if m in titre and m not in domaine:
                marque_titre = m
                break

        if a_mot_de_passe and marque_titre:
            raisons.append(
                f"La page demande un mot de passe et se presente comme << {marque_titre} >>, "
                f"alors qu'elle est hebergee sur << {domaine} >>. Tres probable faux formulaire de connexion."
            )
        elif a_mot_de_passe and extraire_domaine(lien).split(".")[-1] in TLD_SUSPECTS:
            raisons.append(
                "La page demande un mot de passe et utilise une extension a risque. Mefiance."
            )
    except Exception:
        pass
    return raisons


def lire_qr_code(chemin_image):
    """Extrait le ou les liens contenus dans une image de QR code.
    Renvoie la liste des URL trouvees (souvent une seule)."""
    if not QR_DISPONIBLE:
        return []
    try:
        resultats = _qr_decode(_PILImage.open(chemin_image))
        return [res.data.decode("utf-8", errors="ignore") for res in resultats]
    except Exception:
        return []


def analyser_securite(lien, suivre_redirections=True, analyser_page=False):
    score = 0
    raisons = []

    # AMELIORATION : demasquer les liens raccourcis / redirections
    lien_original = lien
    if suivre_redirections:
        finale, etapes = resoudre_redirections(lien)
        if etapes and extraire_domaine(finale) != extraire_domaine(lien_original):
            score += 30
            raisons.append(
                f"Ce lien redirige en realite vers un autre site : << {extraire_domaine(finale)} >>. "
                f"L'adresse de depart cachait sa vraie destination (technique des liens raccourcis)."
            )
            lien = finale  # on analyse la vraie destination

    domaine = domaine_ou_ip(lien)

    # AMELIORATION : liste blanche -> on ne signale jamais un vrai site connu
    if est_domaine_legitime(lien):
        return {"score": 0, "verdict": "sur", "domaine": domaine,
                "raisons": ["Ce domaine fait partie des sites legitimes connus. "
                            "Reste tout de meme vigilant : verifie l'orthographe exacte du domaine."]}

    if est_une_adresse_ip(lien):
        score += 40
        raisons.append("Le lien pointe vers une adresse IP brute (des chiffres) au lieu d'un nom de site. Les sites legitimes utilisent un nom, pas une adresse numerique.")

    if a_arobase_trompeur(lien):
        score += 45
        raisons.append("Le lien contient un << @ >> : le navigateur ira en realite sur ce qui suit l'arobase, pas sur le site affiche avant. Piege tres courant.")

    if not utilise_https(lien):
        score += 20
        raisons.append("Le lien n'utilise pas HTTPS : la connexion n'est pas securisee. Les sites serieux sont toujours en https.")

    marque_deguisee = contient_marque_deguisee(lien)
    if marque_deguisee:
        score += 45
        raisons.append(f"Le lien affiche << {marque_deguisee} >> pour te rassurer, mais le vrai site est << {domaine} >>. C'est un deguisement classique.")

    marque_proche = ressemble_a_une_marque(lien)
    if marque_proche and not marque_deguisee:
        score += 40
        raisons.append(f"Le domaine << {domaine} >> imite << {marque_proche} >> sans etre identique (lettres remplacees par des chiffres, fautes...). Piege pour l'oeil.")

    if a_une_redirection_cachee(lien):
        score += 35
        raisons.append("Ce lien contient une redirection cachee vers un autre site dans ses parametres. L'adresse visible parait sure mais sert de tremplin.")

    if a_des_caracteres_trompeurs(lien):
        score += 45
        raisons.append("Le domaine contient des caracteres d'un autre alphabet qui ressemblent a nos lettres (ex : un << a >> cyrillique). C'est fait pour tromper l'oeil.")

    if a_trop_de_sous_domaines(lien):
        score += 20
        raisons.append("Le lien empile beaucoup de sous-domaines pour noyer le vrai site et faire croire qu'il appartient a une marque connue.")

    tld = tld_suspect(lien)
    if tld:
        score += 15
        raisons.append(f"L'extension << .{tld} >> est tres utilisee par les sites frauduleux (souvent gratuite et sans controle).")

    age = age_domaine_en_jours(lien)
    if age is not None and age < 90:
        score += 20
        raisons.append(f"Ce domaine a ete cree il y a seulement {age} jours. Les sites d'arnaque sont souvent tout recents.")

    mots = contient_mots_hameconnage(lien)
    if len(mots) >= 2:
        score += 15
        raisons.append(
            f"L'adresse contient plusieurs mots typiques des arnaques ({', '.join(mots[:3])}) "
            f"destines a te mettre en confiance ou a t'alarmer."
        )

    complexite = url_trop_longue_ou_complexe(lien)
    if complexite:
        score += 15
        raisons.append(
            "L'adresse est anormalement longue ou remplie de caracteres speciaux, "
            "une facon de noyer et cacher le vrai site."
        )

    # AMELIORATION : analyse du contenu reel de la page (optionnel, visite le site)
    if analyser_page:
        for r in analyser_contenu_page(lien):
            score += 35
            raisons.append(r)

    score = min(score, 100)

    if score >= 60:
        verdict = "dangereux"
    elif score >= 25:
        verdict = "douteux"
    else:
        verdict = "sur"

    if not raisons:
        raisons.append("Aucun signal d'alerte evident detecte. Cela ne garantit PAS que le lien est sur : verifie toujours l'expediteur et ne donne jamais tes mots de passe.")

    return {"score": score, "verdict": verdict, "domaine": domaine, "raisons": raisons}
