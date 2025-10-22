from flask import Flask, request, jsonify, send_from_directory
import clamd
from flask_cors import CORS   
import traceback

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, resources={r"/upload": {"origins": "*"}})
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024


cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)




@app.route('/')
def root():
    return send_from_directory('.', 'files.html')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    if not f or f.filename == '':
        return jsonify({'safe': False, 'message': 'No file provided'}), 400
    try:
        f.stream.seek(0)
        res = cd.instream(f.stream)
        status, sig = list(res.values())[0]
        if status == 'FOUND':
            return jsonify({'safe': False, 'message': 'Infected file detected!', 'viruses': [sig]})
        return jsonify({'safe': True, 'message': 'File is clean'})
    except Exception as e:
        traceback.print_exc()   # log full stack trace to the Flask console
        return jsonify({'safe': False, 'message': f'Scan failed: {e}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
