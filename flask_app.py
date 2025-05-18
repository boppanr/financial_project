from flask import Flask, request, jsonify
import uuid
from dynamo_connection import get_dynamo_table, insert_config_data
import boto3
from botocore.exceptions import ClientError
import threading
from main import main

app = Flask(__name__)
TABLE_NAME = "ConfigTable"

def run_main_async(config_data):
    thread = threading.Thread(target=main, args=(config_data,))
    thread.start()

@app.route('/api/upload_config', methods=['POST'])
def upload_config():
    try:
        config_data = request.get_json()

        if not config_data:
            return jsonify({"error": "Invalid or empty JSON"}), 400

        config_data['config_id'] = str(uuid.uuid4())

        table = get_dynamo_table(TABLE_NAME)
        insert_config_data(table, config_data)

        run_main_async(config_data)

        return jsonify({
            "message": "Configuration inserted and main() triggered asynchronously",
            "config_id": config_data['config_id']
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_config/<config_id>', methods=['GET'])
def get_config(config_id):
    try:
        table = get_dynamo_table(TABLE_NAME)
        response = table.get_item(Key={'config_id': config_id})

        if 'Item' not in response:
            return jsonify({"error": "Configuration not found"}), 404

        return jsonify(response['Item']), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
