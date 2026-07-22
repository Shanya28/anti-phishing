from flask import Flask

app = Flask(__name__)

@app.route("/")
def accueil():
    return "Mon détecteur de phishing arrive bientôt !"

if __name__ == "__main__":
    app.run(debug=True)