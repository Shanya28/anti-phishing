# -*- coding: utf-8 -*-
"""
entrainer_modele.py — Etape 2 : entrainement du modele ML sur de VRAIES donnees.

Entraine un detecteur de phishing sur des milliers d'emails reels etiquetes.
Suit les 6 etapes du machine learning.

PREPARATION : place le(s) CSV dans le meme dossier. Gere deux formats :
  - colonne 'text_combined' + 'label'   (ex: phishing_email.csv)
  - colonnes 'subject' + 'body' + 'label' (ex: CEAS_08.csv, Enron.csv)
label : 0 = legitime, 1 = phishing.
Ajoute des fichiers a la liste FICHIERS pour fusionner (plus de donnees = mieux).

Lancer :  python entrainer_modele.py
"""
import pandas as pd
import warnings
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

warnings.filterwarnings("ignore")

FICHIERS = [
    "phishing_email.csv",
    # "CEAS_08.csv",
    # "Enron.csv",
    # "Nigerian_Fraud.csv",
    # "SpamAssasin.csv",
]

def charger_un_fichier(chemin):
    df = pd.read_csv(chemin)
    if "text_combined" in df.columns:
        texte = df["text_combined"].astype(str)
    elif "body" in df.columns:
        sujet = df["subject"].astype(str) if "subject" in df.columns else ""
        texte = (sujet + " " + df["body"].astype(str))
    else:
        raise ValueError(f"{chemin} : colonnes de texte introuvables")
    petit = pd.DataFrame({"message": texte, "label": df["label"]})
    petit = petit.dropna(subset=["message", "label"])
    petit["label"] = petit["label"].map({0: "legitime", 1: "phishing"})
    return petit.dropna(subset=["label"])

print("1. Chargement des donnees...")
morceaux = []
for f in FICHIERS:
    try:
        d = charger_un_fichier(f)
        morceaux.append(d)
        print(f"   {f} : {len(d)} messages")
    except Exception as e:
        print(f"   (ignore {f} : {e})")

donnees = pd.concat(morceaux, ignore_index=True).drop_duplicates(subset=["message"])
print(f"   TOTAL : {len(donnees)} messages | {donnees['label'].value_counts().to_dict()}")

X, y = donnees["message"], donnees["label"]

print("2. Separation entrainement (80%) / test (20%)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("3. Transformation TF-IDF...")
vectoriseur = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=3, max_features=50000)
X_train_num = vectoriseur.fit_transform(X_train)
X_test_num = vectoriseur.transform(X_test)

print("4. Entrainement...")
modele = LogisticRegression(max_iter=1000)
modele.fit(X_train_num, y_train)

print("5. Evaluation :\n")
predictions = modele.predict(X_test_num)
print(f"   Taux de reussite : {accuracy_score(y_test, predictions):.1%}\n")
print(classification_report(y_test, predictions, zero_division=0))

joblib.dump(modele, "modele_phishing.joblib")
joblib.dump(vectoriseur, "vectoriseur_phishing.joblib")
print("6. Modele et vectoriseur sauvegardes (.joblib)\nTermine !")
