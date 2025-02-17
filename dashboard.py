from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def dashboard():
    # Load results from the JSON file
    with open("recon_results.json", "r") as f:
        results = json.load(f)
        
    return render_template("dashboard.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)