from flask import Flask, request, jsonify
import sys
import os

# Add current directory to path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import main  # Import main entry point

app = Flask(__name__)

@app.route('/api/run', methods=['GET', 'POST'])
def run_main():
    try:
        if request.method == 'GET':
            return jsonify({
                'status': 'ready',
                'message': 'Flask service is running. Use POST to execute strategy.'
            })

        # POST: run the strategy
        result = main()  # or main(input_data) if it takes params

        return jsonify({
            'status': 'success',
            'message': 'Strategy executed successfully.'
        }), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
