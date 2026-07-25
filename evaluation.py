# -*- coding: utf-8 -*-
"""
evaluation.py — Mesure les performances du détecteur.

Idée : on donne à l'outil une liste de liens dont on connaît la vraie nature
(sain ou piégé), et on regarde s'il se trompe. Ça transforme "je crois que ça
marche" en "voici mes chiffres". C'est la démarche qui fait sérieux en démo.

Lancer :  python evaluation.py

Note : les liens "piégés" ci-dessous sont des exemples FICTIFS construits pour
illustrer les techniques, pas de vrais sites malveillants.
"""

from securite import analyser_securite

# (lien, nature_attendue)  ->  "sain" ou "piege"
JEU_DE_TEST = [
    # --- liens sains (dont des cas "pieges pour l'outil" : mots sensibles legitimes) ---
    ("https://www.paypal.com/fr/login", "sain"),
    ("https://www.google.com", "sain"),
    ("https://mail.google.com/mail/u/0", "sain"),
    ("https://www.amazon.fr/gp/cart", "sain"),
    ("https://fr.wikipedia.org/wiki/Hameçonnage", "sain"),
    ("https://www.laposte.fr/particulier", "sain"),
    ("https://github.com/features", "sain"),
    ("https://www.ameli.fr/assure", "sain"),
    ("https://www.leboncoin.fr/recherche", "sain"),
    ("https://www.netflix.com/browse", "sain"),
    ("https://accounts.google.com/signin", "sain"),   # 'accounts'+'signin' mais legitime
    ("https://secure.paypal.com/myaccount", "sain"),  # 'secure' mais vrai paypal
    ("https://applepie-recipes.com/tarte", "sain"),   # contient 'apple' mais sain
    ("https://www.service-public.fr/particuliers", "sain"),
    ("https://login.microsoftonline.com/", "sain"),   # 'login' mais legitime
    # --- liens piégés (fictifs) ---
    ("https://paypal.arnaque.com/verif", "piege"),
    ("https://paypa1-securite.com/compte", "piege"),
    ("https://p4ypal.net/login", "piege"),
    ("https://ex.test/login?redirect=https://fake-login.example", "piege"),
    ("https://paypal.com@arnaque.ru/verif", "piege"),
    ("http://192.168.4.10/login", "piege"),
    ("http://secure-verify-account.tk/login", "piege"),
    ("http://laposte-colis-suivi.xyz/payer", "piege"),
    ("http://ameli-remboursement-secure.ml/connexion", "piege"),
    ("https://secure.login.paypal.verify.xyz.com/account", "piege"),
    ("http://impots-gouv-remboursement.top/valider", "piege"),
    ("http://amaz0n-livraison-suivi.xyz/colis", "piege"),
    ("http://netflix-paiement-refuse.cf/update", "piege"),
]


def evaluer():
    vrais_positifs = 0   # piège correctement détecté
    vrais_negatifs = 0   # sain correctement laissé passer
    faux_positifs = 0    # sain marqué à tort comme suspect
    faux_negatifs = 0    # piège raté

    print(f"{'LIEN':52} {'ATTENDU':8} {'VERDICT':10} {'RÉSULTAT'}")
    print("-" * 90)

    for lien, attendu in JEU_DE_TEST:
        # on n'active pas le réseau ici pour un test rapide et reproductible
        r = analyser_securite(lien, suivre_redirections=False)
        # règle : "douteux" ou "dangereux" = considéré détecté
        detecte = r["verdict"] in ("douteux", "dangereux")

        if attendu == "piege":
            if detecte:
                vrais_positifs += 1
                res = "OK"
            else:
                faux_negatifs += 1
                res = "RATÉ (faux négatif)"
        else:  # sain
            if detecte:
                faux_positifs += 1
                res = "FAUSSE ALERTE (faux positif)"
            else:
                vrais_negatifs += 1
                res = "OK"

        court = lien[:50]
        print(f"{court:52} {attendu:8} {r['verdict']:10} {res}")

    print("-" * 90)
    nb_pieges = vrais_positifs + faux_negatifs
    nb_sains = vrais_negatifs + faux_positifs
    taux_detection = 100 * vrais_positifs / nb_pieges if nb_pieges else 0
    taux_faux_alerte = 100 * faux_positifs / nb_sains if nb_sains else 0

    print(f"\nRÉSULTATS :")
    print(f"  Pièges détectés     : {vrais_positifs}/{nb_pieges}  ({taux_detection:.0f}% de détection)")
    print(f"  Liens sains OK      : {vrais_negatifs}/{nb_sains}  ({taux_faux_alerte:.0f}% de fausses alertes)")
    print(f"  Faux négatifs (ratés)      : {faux_negatifs}")
    print(f"  Faux positifs (fausses alertes) : {faux_positifs}")


if __name__ == "__main__":
    evaluer()
