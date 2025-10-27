from flask import Flask, request, render_template
from scoring import calculate_malware_score

app = Flask(__name__)
@app.route('/')
def home ():  
    return  render_template('index.html')
@app.route('/scan', methods=['POST'])
def scan():
    
    
    
if __name__ == "__main__":
    app.run(debug=True)

    