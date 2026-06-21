"""Flask web dashboard for Optisec WiFi Monitor."""

import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request, redirect, url_for


def create_app(components: dict) -> Flask:
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.secret_key = 'optisec-wifi-monitor-secret-key-2024'

    db = components['db']
    config = components['config']
    alert_mgr = components['alert_mgr']
    device_monitor = components.get('device_monitor')
    attack_detector = components.get('attack_detector')
    enc_auditor = components.get('enc_auditor')
    ai_engine = components.get('ai_engine')

    # --- Page Routes ---

    @app.route('/')
    def index():
        return redirect(url_for('dashboard'))

    @app.route('/dashboard')
    def dashboard():
        stats = db.get_stats()
        return render_template('dashboard.html', stats=stats, page='dashboard')

    @app.route('/devices')
    def devices():
        return render_template('devices.html', page='devices')

    @app.route('/attacks')
    def attacks():
        return render_template('attacks.html', page='attacks')

    @app.route('/encryption')
    def encryption():
        return render_template('encryption.html', page='encryption')

    @app.route('/reports')
    def reports():
        return render_template('reports.html', page='reports')

    # --- API Routes ---

    @app.route('/api/stats')
    def api_stats():
        stats = db.get_stats()
        alerts_by_hour = db.get_alerts_by_hour(24)
        attacks_by_type = db.get_attacks_by_type()
        return jsonify({
            'stats': stats,
            'alerts_by_hour': alerts_by_hour,
            'attacks_by_type': attacks_by_type,
            'timestamp': datetime.now().isoformat(),
        })

    @app.route('/api/devices')
    def api_devices():
        devices = db.get_all_devices()
        whitelist = set(m.upper() for m in config.whitelist)
        for d in devices:
            d['whitelisted'] = d.get('mac', '').upper() in whitelist
        return jsonify({'devices': devices, 'total': len(devices)})

    @app.route('/api/alerts')
    def api_alerts():
        limit = int(request.args.get('limit', 50))
        unresolved = request.args.get('unresolved', 'false').lower() == 'true'
        alerts = db.get_alerts(limit=limit, unresolved_only=unresolved)
        return jsonify({'alerts': alerts, 'total': len(alerts)})

    @app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
    def api_resolve_alert(alert_id):
        db.resolve_alert(alert_id)
        return jsonify({'status': 'ok', 'alert_id': alert_id})

    @app.route('/api/attacks')
    def api_attacks():
        limit = int(request.args.get('limit', 50))
        attacks = db.get_attacks(limit=limit)
        return jsonify({'attacks': attacks, 'total': len(attacks)})

    @app.route('/api/encryption')
    def api_encryption():
        audits = db.get_audits(limit=100)
        summary = enc_auditor.get_audit_summary() if enc_auditor else {}
        return jsonify({'audits': audits, 'summary': summary})

    @app.route('/api/whitelist', methods=['GET'])
    def api_whitelist_get():
        return jsonify({'whitelist': config.whitelist})

    @app.route('/api/whitelist', methods=['POST'])
    def api_whitelist_add():
        data = request.get_json()
        mac = data.get('mac', '').upper()
        if mac:
            config.add_to_whitelist(mac)
            db.set_whitelist(mac, True)
            alert_mgr.info("WHITELIST", f"Device {mac} added to whitelist")
            return jsonify({'status': 'ok', 'mac': mac})
        return jsonify({'status': 'error', 'message': 'Invalid MAC'}), 400

    @app.route('/api/whitelist/<mac>', methods=['DELETE'])
    def api_whitelist_remove(mac):
        mac = mac.upper()
        config.remove_from_whitelist(mac)
        db.set_whitelist(mac, False)
        return jsonify({'status': 'ok', 'mac': mac})

    @app.route('/api/reports')
    def api_reports():
        reports = db.get_reports(limit=10)
        return jsonify({'reports': reports})

    @app.route('/api/reports/generate', methods=['POST'])
    def api_generate_report():
        if not ai_engine:
            return jsonify({'status': 'error', 'message': 'AI engine not available'}), 503
        try:
            report = ai_engine.generate_periodic_report()
            return jsonify({'status': 'ok', 'report': report})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ai/ask', methods=['POST'])
    def api_ai_ask():
        if not ai_engine:
            return jsonify({'status': 'error', 'message': 'AI engine not available'}), 503
        data = request.get_json()
        question = data.get('question', '')
        if not question:
            return jsonify({'status': 'error', 'message': 'No question provided'}), 400
        try:
            answer = ai_engine.ask(question)
            return jsonify({'status': 'ok', 'answer': answer})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/ai/analyze-device', methods=['POST'])
    def api_analyze_device():
        if not ai_engine:
            return jsonify({'status': 'error', 'message': 'AI engine not available'}), 503
        data = request.get_json()
        try:
            result = ai_engine.generate_device_report(data)
            return jsonify({'status': 'ok', 'analysis': result})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/config', methods=['GET'])
    def api_config_get():
        safe_config = {
            'monitor_interface': config.monitor_interface,
            'internet_interface': config.internet_interface,
            'language': config.language,
            'scan_interval': config.get('scan_interval', 30),
            'ai_report_interval': config.get('ai_report_interval', 300),
            'has_api_key': bool(config.openrouter_api_key),
        }
        return jsonify(safe_config)

    @app.route('/api/config', methods=['POST'])
    def api_config_set():
        data = request.get_json()
        allowed = ['language', 'scan_interval', 'ai_report_interval']
        for key in allowed:
            if key in data:
                config.set(key, data[key])
        return jsonify({'status': 'ok'})

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404

    return app
