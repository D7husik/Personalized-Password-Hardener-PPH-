# from flask import Flask, render_template, request, jsonify
# from pph_core import PasswordHardener
# import json

# app = Flask(__name__)
# pph = PasswordHardener()

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/harden', methods=['POST'])
# def harden_password():
#     try:
#         data = request.json
#         base_password = data.get('password', '')
#         metadata = {
#             'house_name': data.get('house_name', ''),
#             'phone_suffix': data.get('phone_suffix', ''),
#             'core_memory': data.get('core_memory', ''),
#             'handle_name': data.get('handle_name', ''),
#             'birthday_token': data.get('birthday_token', ''),
#             'custom': data.get('custom', '')
#         }
        
#         if not base_password:
#             return jsonify({'error': 'Password is required'}), 400
        
#         # Harden the password
#         result = pph.harden_password(base_password, metadata)
        
#         # Analyze original and hardened passwords
#         original_analysis = pph.analyze_password_strength(base_password)
#         hardened_analysis = pph.analyze_password_strength(result['hardened_medium'])
        
#         response = {
#             'success': True,
#             'original': {
#                 'password': base_password,
#                 'analysis': original_analysis
#             },
#             'hardened': {
#                 'short': result['hardened_short'],
#                 'medium': result['hardened_medium'],
#                 'long': result['hardened_long'],
#                 'short_entropy': result['short_entropy'],
#                 'medium_entropy': result['medium_entropy'],
#                 'long_entropy': result['long_entropy'],
#                 'analysis': hardened_analysis
#             },
#             'crypto_details': {
#                 'algorithm': 'PBKDF2-HMAC-SHA256',
#                 'iterations': result['iterations'],
#                 'salt': result['salt']
#             }
#         }
        
#         return jsonify(response)
    
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/analyze', methods=['POST'])
# def analyze_password():
#     try:
#         data = request.json
#         password = data.get('password', '')
        
#         if not password:
#             return jsonify({'error': 'Password is required'}), 400
        
#         analysis = pph.analyze_password_strength(password)
        
#         return jsonify({
#             'success': True,
#             'analysis': analysis
#         })
    
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/simulate-brute-force', methods=['POST'])
# def simulate_brute_force():
#     try:
#         data = request.json
#         password = data.get('password', '')
#         max_attempts = data.get('max_attempts', 10000)
        
#         if not password:
#             return jsonify({'error': 'Password is required'}), 400
        
#         result = pph.simulate_brute_force(password, max_attempts)
        
#         return jsonify({
#             'success': True,
#             'result': result
#         })
    
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# if __name__ == '__main__':
#     app.run(debug=True, port=5000)