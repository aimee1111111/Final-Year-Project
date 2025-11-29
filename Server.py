from flask import Flask, request, jsonify, send_from_directory
import clamd
import yara
from flask_cors import CORS
import traceback
import os

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB

# --- Engines ---------------------------------------------------------------

# ClamAV (expects a local clamd listening on 3310)
cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)

# YARA: load ONLY from external rules file
YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', 'rules.yar')
yara_rules = None
try:
    if os.path.exists(YARA_RULES_PATH):
        yara_rules = yara.compile(filepath=YARA_RULES_PATH)
        print(f"[YARA] Rules loaded from: {YARA_RULES_PATH}")
    else:
        print(f"[YARA] Rules file not found at: {YARA_RULES_PATH}. YARA scanning will be disabled.")
except Exception as e:
    print(f"[YARA] Failed to load rules: {e}. YARA scanning will be disabled.")
    yara_rules = None


def scan_with_clamav(file_stream):
    """Scan file with ClamAV."""
    try:
        file_stream.seek(0)
        res = cd.instream(file_stream)
        status, sig = list(res.values())[0]
        if status == 'FOUND':
            return {'safe': False, 'engine': 'ClamAV', 'threat': sig}
        return {'safe': True, 'engine': 'ClamAV'}
    except Exception as e:
        return {'safe': None, 'engine': 'ClamAV', 'error': str(e)}


def scan_with_yara(file_stream):
    """Scan file with YARA rules (in-memory)."""
    if not yara_rules:
        return {'safe': None, 'engine': 'YARA', 'error': 'YARA rules not loaded'}

    try:
        file_stream.seek(0)
        data = file_stream.read()  # bytes
        matches = yara_rules.match(data=data)

        if matches:
            threats = [{'rule': m.rule, 'tags': m.tags, 'meta': m.meta} for m in matches]
            return {'safe': False, 'engine': 'YARA', 'threats': threats}

        return {'safe': True, 'engine': 'YARA'}
    except Exception as e:
        return {'safe': None, 'engine': 'YARA', 'error': str(e)}


# --- Routes ----------------------------------------------------------------

@app.route('/')
def root():
    return send_from_directory('.', 'files.html')


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    if not f or f.filename == '':
        return jsonify({'safe': False, 'message': 'No file provided'}), 400

    try:
        # Run both engines
        clamav_result = scan_with_clamav(f.stream)
        yara_result = scan_with_yara(f.stream)

        threats = []
        scan_results = []

        # ClamAV
        if clamav_result['safe'] is False:
            threats.append(f"ClamAV: {clamav_result['threat']}")
            scan_results.append({'engine': 'ClamAV', 'status': 'threat_detected',
                                 'details': clamav_result['threat']})
        elif clamav_result['safe'] is True:
            scan_results.append({'engine': 'ClamAV', 'status': 'clean'})
        else:
            scan_results.append({'engine': 'ClamAV', 'status': 'error',
                                 'error': clamav_result.get('error')})

        # YARA
        if yara_result['safe'] is False:
            for t in yara_result['threats']:
                rule_name = t['rule']
                desc = (t.get('meta') or {}).get('description', 'No description')
                threats.append(f"YARA: {rule_name} - {desc}")
            scan_results.append({'engine': 'YARA', 'status': 'threat_detected',
                                 'details': yara_result['threats']})
        elif yara_result['safe'] is True:
            scan_results.append({'engine': 'YARA', 'status': 'clean'})
        else:
            scan_results.append({'engine': 'YARA', 'status': 'error',
                                 'error': yara_result.get('error')})

        # Response
        if threats:
            return jsonify({
                'safe': False,
                'message': 'Threats detected!',
                'threats': threats,
                'scan_results': scan_results
            })

        errors = [r for r in scan_results if r['status'] == 'error']
        if errors:
            return jsonify({
                'safe': False,
                'message': 'Scan completed with errors',
                'scan_results': scan_results
            }), 500

        return jsonify({
            'safe': True,
            'message': 'File is clean (scanned by ClamAV and YARA)',
            'scan_results': scan_results
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'safe': False, 'message': f'Scan failed: {e}'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)