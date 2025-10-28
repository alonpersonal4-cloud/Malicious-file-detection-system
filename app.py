import tempfile
from flask import Flask, request, render_template
from scoring import calculate_malware_score
import os

app = Flask(__name__)
@app.route("/")
def home ():  
    return  render_template("index.html")
@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return "No found a file"
    else:
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            file = request.files["file"]
            file.save(temp.name)
            file_path = temp.name
        result = calculate_malware_score(file_path)
        Dictionary ={
            "risk_level": result[0],
            "explanations": result[1],
            "score": result[2]
        }
        os.remove(file_path)
        return render_template('index.html', result=Dictionary)
    
if __name__ == "__main__":
    app.run(debug=True)

    