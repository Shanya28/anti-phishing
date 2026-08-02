"""
sécurité.py — Le cerveau "cybersécurité" du détecteur de phishing.
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
pedagogique. Il ne remplacé PAS un vrai service de sécurité, et ne doit jamais
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
    import whois
    WHOIS_DISPONIBLE = True
except Exception:
    WHOIS_DISPONIBLE = False



import re as _re

def ressemble_a_un_lien(texte):
    """Verifie basiquement que le texte a la forme d'un lien/domaine.
    Un vrai lien a au moins un point et une extension de 2+ lettres
    (exemple.com, site.fr...). Rejette le charabia type 'SWDFGYHUIOP^$'."""
    t = (texte or "").strip()
    if not t:
        return False
    # on retire un eventuel schema pour regarder juste l'hote
    hote = _re.sub(r'^https?://', '', t, flags=_re.IGNORECASE).split('/')[0].split('?')[0]
    # doit contenir un point, et finir par une extension de lettres (.com, .fr, .xyz...)
    if '.' not in hote:
        return False
    # cas 1 : adresse IP (ex 192.168.1.1) -> c'est un lien valide (et suspect)
    hote_sans_port = hote.split(':')[0].split('@')[-1]
    parties = hote_sans_port.split('.')
    if len(parties) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parties):
        return True
    # cas 2 : nom de domaine. On accepte les lettres UNICODE (et pas seulement
    # a-z) : un domaine avec des caracteres cyrilliques ou grecs est justement
    # une attaque homographe qu'il faut ANALYSER et signaler, pas rejeter en
    # bloc. Le refus doit viser le charabia, pas les liens dangereux.
    return bool(_re.match(r'^[\w@.\-_:]+\.[^\W\d_]{2,}$', hote, _re.UNICODE))


# Caracteres unicode que les navigateurs traitent comme un point separateur
# de domaine. Les attaquants s'en servent pour casser la detection.
_POINTS_UNICODE = ["\u3002", "\uff0e", "\uff61", "\u0589", "\u06d4"]



def extraire_lien_du_texte(texte):
    """Extrait le premier lien d'un texte. Beaucoup de gens collent le message
    entier ("Regarde ca https://... c'est bien") plutot que le lien seul :
    plutot que de les rejeter, on retrouve le lien pour eux.
    Nettoie aussi la ponctuation collee (guillemets, parentheses, point final)."""
    t = (texte or "").strip()
    # retirer guillemets et parentheses englobants
    for ouvre, ferme in [('"', '"'), ("'", "'"), ("(", ")"), ("[", "]"), ("<", ">")]:
        if t.startswith(ouvre) and t.endswith(ferme) and len(t) > 2:
            t = t[1:-1].strip()

    # chercher un lien avec schema explicite
    m = _re.search(r'(?i)\b(?:https?://|www\.)\S+', t)
    if m:
        candidat = m.group(0)
    elif " " not in t:
        candidat = t          # pas d'espace : c'est deja le lien seul
    else:
        # texte sans schema : chercher un mot qui ressemble a un domaine
        m2 = _re.search(r'\b[\w\-]+(?:\.[\w\-]+)+\b', t)
        candidat = m2.group(0) if m2 else t

    # retirer la ponctuation collee a la fin
    return candidat.rstrip('.,;:!?)"\'>]')


def normaliser(lien):
    """Ramene le lien a une forme canonique AVANT toute analyse.
    Etape essentielle : sans elle, un attaquant contourne la detection en
    encodant une lettre (%70aypal) ou en utilisant un point unicode
    (paypal。arnaque.com), que le navigateur interprete normalement."""
    lien = (lien or "").strip()

    # 1) decoder l'encodage pourcent (%70 -> p), plusieurs fois si imbrique
    for _ in range(5):
        decode = unquote(lien)
        if decode == lien:
            break
        lien = decode

    # 2) remplacer les points unicode par un vrai point
    for p in _POINTS_UNICODE:
        lien = lien.replace(p, ".")

    # 3) retirer les espaces insecables et caracteres invisibles
    for invisible in ["\u00a0", "\u200b", "\u200c", "\u200d", "\ufeff", " "]:
        lien = lien.replace(invisible, "")

    # comparaison en minuscules : "HTTPS://..." est un schema valide
    bas = lien.lower()
    if not bas.startswith("http://") and not bas.startswith("https://"):
        # un data: ou javascript: n'est PAS un lien web normal
        if bas.startswith(("data:", "javascript:", "file:", "vbscript:")):
            return lien
        lien = "http://" + lien
    return lien


def est_schema_dangereux(lien):
    """data:, javascript:, file: ne sont pas des liens vers un site : ils
    executent du contenu ou lisent des fichiers locaux. Toujours suspects."""
    t = (lien or "").strip().lower()
    for _ in range(3):
        d = unquote(t)
        if d == t:
            break
        t = d
    return t.startswith(("data:", "javascript:", "file:", "vbscript:"))


def extraire_hote(lien):
    hote = urlparse(normaliser(lien)).netloc.lower()
    if "@" in hote:
        hote = hote.split("@")[-1]
    return hote.split(":")[0]


# Suffixes publics composes : dans bbc.co.uk, le vrai domaine est "bbc.co.uk"
# et non "co.uk". Prendre betement les deux dernieres parties casse ces cas.
_SUFFIXES_COMPOSES = {
    # Royaume-Uni, Japon, Coree, Oceanie
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.kr", "or.kr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    # Ameriques
    "com.br", "net.br", "org.br", "gov.br", "com.mx", "org.mx", "com.ar",
    "com.co", "com.pe", "com.ve", "com.uy", "com.ec", "com.bo",
    # Europe (dont .com.ru, .net.ru, .org.ru souvent utilises par le phishing)
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru",
    "com.ua", "co.ua", "in.ua", "com.pl", "com.es", "com.pt", "com.de",
    "com.tr", "gen.tr", "org.tr", "com.gr", "com.ro", "com.hr", "com.cy",
    "gouv.fr", "asso.fr", "tm.fr", "com.fr", "nom.fr", "prd.fr",
    # Afrique
    "co.za", "org.za", "net.za", "co.ke", "or.ke", "com.ng", "org.ng",
    "com.gh", "com.eg", "com.ma", "com.tn", "com.dz", "co.bw", "co.zw",
    # Asie
    "co.in", "net.in", "org.in", "gov.in", "com.cn", "net.cn", "org.cn",
    "gov.cn", "com.tw", "com.sg", "com.hk", "com.my", "com.ph", "co.th",
    "in.th", "com.vn", "com.pk", "com.bd", "com.np", "co.id", "web.id",
    # Moyen-Orient
    "co.il", "org.il", "com.sa", "com.ae", "com.qa", "com.kw", "com.lb",
}

# Prefixes qui, suivis d'une extension de 2 lettres (pays), forment un suffixe
# compose. Regle generale : attrape les cas absents de la liste ci-dessus.
_PREFIXES_SUFFIXE = {"com", "net", "org", "co", "gov", "edu", "ac", "or", "ne", "go"}

# Extensions de marque : Microsoft possede ".microsoft", Google ".google", etc.
# Sur ces TLD, TOUT sous-domaine appartient a la marque : forms.cloud.microsoft
# est un service officiel Microsoft, pas une usurpation.
_TLD_DE_MARQUE = {
    "microsoft", "google", "apple", "amazon", "youtube", "aws", "azure",
    "dev", "app", "page", "gle", "goog", "bank", "insurance",
}


def extraire_domaine(lien):
    """Renvoie le domaine enregistrable, en tenant compte des suffixes
    composes (bbc.co.uk) et des extensions de marque (forms.cloud.microsoft)."""
    hote = extraire_hote(lien)
    parties = hote.split(".")
    if len(parties) < 2:
        return hote
    # suffixe compose connu : on garde trois parties (bbc.co.uk)
    if len(parties) >= 3 and ".".join(parties[-2:]) in _SUFFIXES_COMPOSES:
        return ".".join(parties[-3:])
    # regle generale : "com.xx" ou xx est un code pays de 2 lettres
    if (len(parties) >= 3 and parties[-2] in _PREFIXES_SUFFIXE
            and len(parties[-1]) == 2 and parties[-1].isalpha()):
        return ".".join(parties[-3:])
    return ".".join(parties[-2:])


def est_tld_de_marque(lien):
    """True si l'extension est un TLD detenu par une marque (.microsoft...).
    Dans ce cas tout sous-domaine est legitime : seule la marque peut en creer."""
    return extraire_hote(lien).split(".")[-1] in _TLD_DE_MARQUE


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

# Domaines légitimes connus : on ne les signale JAMAIS comme suspects.
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
MOTS_HAMECONNAGE = ["secure", "verify", "vérification", "account", "update",
                    "confirm", "login", "signin", "banking", "suspended",
                    "unlock", "recover", "validation", "customer", "webscr",
                    "sécurité", "vérifier", "compte", "connexion", "identifiant"]



# Marques appartenant a une meme entreprise : outlook.office.com est un service
# Microsoft officiel, pas une usurpation. Sans ce regroupement, l'outil signale
# a tort des domaines legitimes tres utilises.
_GROUPES_DE_MARQUES = [
    {"microsoft", "outlook", "office", "live", "msn", "skype", "bing",
     "sharepoint", "onedrive", "azure", "xbox", "hotmail"},
    {"google", "gmail", "youtube", "android", "gle", "goog", "blogger"},
    {"facebook", "instagram", "whatsapp", "messenger", "meta"},
    {"amazon", "aws", "audible", "twitch", "prime"},
    {"apple", "icloud", "itunes"},
    {"laposte", "colissimo", "chronopost"},
]


def _meme_entreprise(marque, domaine):
    """True si la marque et le domaine appartiennent au meme groupe."""
    nom = domaine.split(".")[0]
    for groupe in _GROUPES_DE_MARQUES:
        if marque in groupe and nom in groupe:
            return True
    return False


def contient_marque_deguisee(lien):
    """Detecte une marque connue presente comme MOT SEPARE dans l'hote
    (paypal.arnaque.com) mais absente du vrai domaine. On découpe sur les
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
            # exception : meme entreprise (outlook.office.com, drive.google.com...)
            if _meme_entreprise(marque, domaine):
                continue
            return marque
    return None


def _normaliser_caracteres(mot):
    """Ramene les chiffres/caractères imitant des lettres a leur equivalent.
    Ex: 'p4yp0l' -> 'paypol'. Aide a demasquer le typosquatting."""
    table = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
             "7": "t", "@": "a", "$": "s", "|": "l"}
    return "".join(table.get(c, c) for c in mot.lower())


def ressemble_a_une_marque(lien):
    """Typosquatting AFFINE : détecté les imitations de marque, y compris
    - substitutions de caractères (paypa1, p4ypal)
    - marques noyees dans des mots composes (paypal-france-sécurisé)
    - fautes de 1 a 2 lettres selon la longueur de la marque."""
    domaine = extraire_domaine(lien)
    nom = domaine.split(".")[0]

    # Un vrai domaine de marque peut contenir un tiret la ou la marque n'en a
    # pas (credit-agricole.fr vs "creditagricole"). Sans cette verification,
    # le VRAI site de la banque serait signale comme une imitation.
    nom_colle = nom.replace("-", "").replace("_", "")
    if nom_colle in MARQUES_CONNUES:
        return None

    # on decoupe le nom en morceaux (tirets, underscores) ET on garde le nom entier
    morceaux = nom.replace("_", "-").split("-")
    morceaux.append(nom_colle)  # version collee

    for morceau in morceaux:
        variante = _normaliser_caracteres(morceau)
        for marque in MARQUES_CONNUES:
            # cas 1 : identique apres normalisation mais pas le vrai domaine
            if variante == marque and nom != marque:
                return marque
            # cas 2 : la marque apparait comme MORCEAU separe (paypal-sécurisé),
            # pas noyee dans un mot normal comme "applepie". On exige que le morceau
            # courant SOIT la marque, ou qu'un mot d'hameconnage accompagne.
            if len(marque) >= 5 and marque in variante and variante != marque and nom != marque:
                autres = variante.replace(marque, "")
                # suspect seulement si le reste ressemble a du phishing (mot-cle connu)
                if any(mot in autres for mot in ["secur", "verif", "compte", "account",
                        "login", "france", "service", "client", "support", "official",
                        "confirm", "update", "connexion", "auth"]):
                    return marque
            # cas 3 : très proche (fautes) - seuil selon longueur
            seuil = 1 if len(marque) < 6 else 2
            d = Levenshtein.distance(variante, marque)
            if 0 < d <= seuil and abs(len(variante) - len(marque)) <= seuil:
                return marque
    return None


def a_une_redirection_cachee(lien):
    lien_decode = unquote(lien or "")
    if "?" in lien_decode:
        paramètres = lien_decode.split("?", 1)[1].lower()
        if "http://" in paramètres or "https://" in paramètres:
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



def _retirer_accents(texte):
    """Retire les accents : microsöft -> microsoft."""
    decompose = unicodedata.normalize("NFD", texte)
    return "".join(c for c in decompose if unicodedata.category(c) != "Mn")


def imite_marque_par_accents(lien):
    """Detecte un domaine qui devient une marque connue une fois les accents
    retires : microsöft -> microsoft, päypal -> paypal.
    Un accent n'est pas suspect en soi (sites francais legitimes), mais il
    l'est quand il sert a deguiser une marque."""
    hote = extraire_hote(lien)
    if hote.isascii():
        return None  # pas d'accent, rien a verifier
    for partie in hote.split("."):
        sans_accent = _retirer_accents(partie)
        if sans_accent != partie and sans_accent in MARQUES_CONNUES:
            return sans_accent
    return None



def extension_impossible(lien):
    """True si l'extension contient des chiffres ou caracteres invalides.
    Aucune vraie extension n'en contient : c'est soit une faute de copie,
    soit une tentative d'imitation (micr0soft, g00gle...)."""
    hote = extraire_hote(lien)
    if "." not in hote:
        return False
    ext = hote.split(".")[-1]
    return bool(ext) and not ext.isalpha()



# Caracteres invisibles ou de controle bidirectionnel : servent a faire afficher
# une adresse differente de sa vraie valeur (technique RTL override).
_CARACTERES_INVISIBLES = [
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",   # controles bidirectionnels
    "\u2066", "\u2067", "\u2068", "\u2069",             # isolats
    "\u200b", "\u200c", "\u200d", "\ufeff",             # espaces de largeur nulle
    "\u0000",                                            # octet nul
]


def contient_caracteres_invisibles(lien):
    """True si le lien contient des caracteres invisibles ou d'inversion de
    sens. Aucune adresse legitime n'en contient : c'est toujours une tentative
    de faire afficher autre chose que la vraie destination."""
    brut = unquote(lien or "")
    return any(c in brut or c in (lien or "") for c in _CARACTERES_INVISIBLES)


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




import ipaddress as _ipaddress
import socket as _socket


def adresse_interne(lien):
    """Protection SSRF : True si le lien pointe vers une adresse INTERNE
    (localhost, reseau prive, metadonnees cloud). On ne doit JAMAIS faire de
    requete reseau vers ces adresses : un attaquant pourrait s'en servir pour
    faire explorer le reseau interne du serveur.
    Exemples bloques : 127.0.0.1, localhost, 192.168.x.x, 10.x.x.x,
    169.254.169.254 (metadonnees cloud), [::1]..."""
    try:
        hote = extraire_hote(lien)
        if not hote:
            return True
        # noms explicitement internes
        if hote in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or hote.endswith(".local") \
           or hote.endswith(".internal"):
            return True
        # resoudre le nom en IP (un domaine peut pointer vers une IP privee !)
        try:
            ip_texte = _socket.gethostbyname(hote)
        except Exception:
            # si on ne peut pas resoudre, on considere que c'est risque
            return True
        ip = _ipaddress.ip_address(ip_texte)
        # bloque prive, loopback, lien-local (169.254.x.x), reserve, multicast
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except Exception:
        return True  # en cas de doute, on bloque


def resoudre_redirections(lien):
    """Suit les redirections HTTP pour trouver la VRAIE destination finale.
    Demasque les liens raccourcis (bit.ly...) et les redirections en chaine.
    Renvoie (url_finale, liste_des_etapes) ou (lien, []) si impossible."""
    if not REQUESTS_DISPONIBLE:
        return lien, []
    if adresse_interne(lien):        # protection SSRF
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
    """Une URL anormalement longue ou bourree de caractères speciaux
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
    # caractères d'encodage suspects
    if l.count("%") >= 3:
        raisons.append("encodage")
    return raisons


def age_domaine_en_jours(lien):
    if not WHOIS_DISPONIBLE:
        return None
    try:
        from datetime import datetime
        infos = whois.whois(extraire_domaine(lien))
        création = infos.creation_date
        if isinstance(création, list):
            création = création[0]
        if création is None:
            return None
        return (datetime.now() - création).days
    except Exception:
        return None



def analyser_contenu_page(lien):
    """Recupere la page d'arrivee et cherche des signes de faux formulaire
    de connexion (champ mot de passe + demande d'infos sensibles).
    Ne visite le site QU'UNE fois, avec timeout. Renvoie une liste de raisons."""
    if not (REQUESTS_DISPONIBLE and BS4_DISPONIBLE):
        return []
    if adresse_interne(lien):        # protection SSRF
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
                f"alors qu'elle est hebergee sur << {domaine} >>. Très probable faux formulaire de connexion."
            )
        elif a_mot_de_passe and extraire_domaine(lien).split(".")[-1] in TLD_SUSPECTS:
            raisons.append(
                "La page demande un mot de passe et utilise une extension à risque. Méfiance."
            )
    except Exception:
        pass
    return raisons


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
                f"Ce lien redirige en réalité vers un autre site : << {extraire_domaine(finale)} >>. "
                f"L'adresse de départ cachait sa vraie destination (technique des liens raccourcis)."
            )
            lien = finale  # on analyse la vraie destination

    domaine = domaine_ou_ip(lien)

    # AMELIORATION : liste blanche -> on ne signale jamais un vrai site connu
    if est_domaine_legitime(lien):
        return {"score": 0, "verdict": "sur", "domaine": domaine,
                "raisons": ["Ce domaine fait partie des sites légitimes connus. "
                            "Vérifie tout de même l'orthographe exacte du domaine. "
                            "Et rappelle-toi : je vérifie le lien, pas la véracité de ce qu'on te promet."]}

    if contient_caracteres_invisibles(lien):
        score += 60
        raisons.append(
            "Ce lien contient des caractères invisibles qui servent à afficher "
            "une adresse différente de sa vraie destination. Aucun site honnête "
            "ne fait cela."
        )

    if not domaine or "." not in str(domaine):
        return {"score": 0, "verdict": "sur", "domaine": domaine,
                "raisons": ["Je n'ai pas réussi à lire d'adresse valide dans ce que tu as collé. Vérifie que le lien est complet."]}

    if est_schema_dangereux(lien):
        score += 60
        raisons.append(
            "Ce n'est pas un lien vers un site web normal : il utilise un format "
            "(data:, javascript:...) qui peut exécuter du code directement. "
            "C'est très rarement légitime dans un message reçu."
        )

    if est_une_adresse_ip(lien):
        score += 40
        raisons.append("Le lien pointe vers une adresse IP brute (des chiffres) au lieu d'un nom de site. Les sites légitimes utilisent un nom, pas une adresse numérique.")

    if a_arobase_trompeur(lien):
        score += 45
        raisons.append("Le lien contient un << @ >> : le navigateur ira en réalité sur ce qui suit l'arobase, pas sur le site affiché avant. Piège très courant.")

    if not utilise_https(lien):
        score += 20
        raisons.append("Le lien n'utilise pas HTTPS : la connexion n'est pas sécurisée. Les sites sérieux sont toujours en https.")

    marque_deguisee = contient_marque_deguisee(lien)
    if marque_deguisee and est_tld_de_marque(lien):
        marque_deguisee = None  # ex: forms.cloud.microsoft appartient bien a Microsoft
    if marque_deguisee:
        score += 45
        raisons.append(f"Le lien affiche << {marque_deguisee} >> pour te rassurer, mais le vrai site est << {domaine} >>. C'est un déguisement classique.")

    marque_proche = ressemble_a_une_marque(lien)
    if marque_proche and not marque_deguisee:
        score += 40
        # Aggravant : une marque imitee sur un suffixe compose etranger
        # (goog1e-accounts.com.ru) est un schema de phishing tres courant.
        _d = extraire_domaine(lien)
        if _d.count(".") >= 2:
            score += 25
            raisons.append(
                "Ce domaine imite une marque connue ET utilise une adresse "
                "composée dans un pays étranger : c'est une combinaison très "
                "typique des sites frauduleux."
            )
        raisons.append(f"Le domaine << {domaine} >> imite << {marque_proche} >> sans être identique (lettres remplacées par des chiffres, fautes...). Piège pour l'œil.")

    if a_une_redirection_cachee(lien):
        score += 35
        raisons.append("Ce lien contient une redirection cachée vers un autre site dans ses paramètres. L'adresse visible paraît sûre mais sert de tremplin.")

    marque_accents = imite_marque_par_accents(lien)
    if marque_accents:
        score += 50
        raisons.append(
            f"Le domaine imite « {marque_accents} » en remplaçant une lettre par "
            f"une lettre accentuée. À l'œil nu la différence est presque invisible, "
            f"mais ce n'est pas le vrai site."
        )

    if a_des_caracteres_trompeurs(lien):
        score += 45
        raisons.append("Le domaine contient des caractères d'un autre alphabet qui ressemblent à nos lettres (ex : un << a >> cyrillique). C'est fait pour tromper l'œil.")

    if a_trop_de_sous_domaines(lien):
        score += 20
        raisons.append("Le lien empile beaucoup de sous-domaines pour noyer le vrai site et faire croire qu'il appartient à une marque connue.")

    tld = tld_suspect(lien)
    if tld:
        score += 15
        raisons.append(f"L'extension << .{tld} >> est très utilisée par les sites frauduleux (souvent gratuite et sans contrôle).")

    age = age_domaine_en_jours(lien)
    if age is not None and age < 90:
        score += 20
        raisons.append(f"Ce domaine a ete créé il y a seulement {age} jours. Les sites d'arnaque sont souvent tout récents.")

    mots = contient_mots_hameconnage(lien)
    if len(mots) >= 2:
        score += 15
        raisons.append(
            f"L'adresse contient plusieurs mots typiques des arnaques ({', '.join(mots[:3])}) "
            f"destinés à te mettre en confiance ou à t'alarmer."
        )

    complexite = url_trop_longue_ou_complexe(lien)
    if complexite:
        score += 15
        raisons.append(
            "L'adresse est anormalement longue ou remplie de caractères speciaux, "
            "une façon de noyer et cacher le vrai site."
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
        raisons.append("Aucun signal d'alerte évident détecté sur ce lien. Attention : je vérifie si le lien est piégé, pas si ce qu'on te promet est vrai. Un site techniquement normal peut quand même héberger une arnaque (faux placement, fausse cagnotte, fausse promesse de gain). Ne donne jamais tes mots de passe ni ton argent sans vérifier ailleurs.")

    return {"score": score, "verdict": verdict, "domaine": domaine, "raisons": raisons}
