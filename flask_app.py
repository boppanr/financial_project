from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
from dynamo_connection import convert_floats, get_dynamo_table, insert_config_data
import boto3
from botocore.exceptions import ClientError
import threading
from main import main
from datetime import datetime
#from main import get_broker_pnl
from flask import jsonify

app = Flask(__name__)
CORS(app)
TABLE_NAME = "ConfigTable"

def run_main_async(config_data):
    thread = threading.Thread(target=main, args=(config_data,))
    thread.start()

@app.route('/api/submit_json', methods=['POST'])
def submit_json_to_db():
    config_data = request.get_json()
    
    if not config_data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    config_data.setdefault('config_id', str(uuid.uuid4()))
    config_data['creation_time'] = datetime.utcnow().isoformat()

    try:
        table = get_dynamo_table(TABLE_NAME)
        insert_config_data(table, config_data)
        return jsonify({
            "message": "Data inserted successfully",
            "config_id": config_data['config_id']
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload_config', methods=['POST'])
def upload_config():
    try:
        config_data = request.get_json()

        if not config_data:
            return jsonify({"error": "Invalid or empty JSON"}), 400

        config_data['config_id'] = str(uuid.uuid4())
        config_data['creation_time'] = datetime.utcnow().isoformat()

        table = get_dynamo_table(TABLE_NAME)
        insert_config_data(table, config_data)

        run_main_async(config_data)

        return jsonify({
            "message": "Configuration inserted and main() triggered asynchronously",
            "config_id": config_data['config_id']
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/get_config_by_details', methods=['GET'])
def get_config_by_details():
    customer_name = request.args.get('customer_name')
    provider = request.args.get('provider')
    userid = request.args.get('userid')

    if not all([customer_name, provider, userid]):
        return jsonify({"error": "Missing required query parameters"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)
        response = table.scan(
            FilterExpression=(
                "customer_name = :customer_name AND provider = :provider AND userid = :userid "
                "AND (attribute_not_exists(is_deleted) OR is_deleted = :false)"
            ),
            ExpressionAttributeValues={
                ":customer_name": customer_name,
                ":provider": provider,
                ":userid": userid,
                ":false": False
            }
        )

        items = response.get('Items', [])
        
        if not items:
            return jsonify({"error": "No matching active records found"}), 404

        return jsonify(items), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

@app.route('/api/update_config', methods=['PUT'])
def update_config_by_details():
    data = request.get_json()
    
    customer_name = data.get('customer_name')
    provider = data.get('provider')
    userid = data.get('userid')
    updated_fields = data.get('updated_fields')

    if not all([customer_name, provider, userid, updated_fields]):
        return jsonify({"error": "Missing required parameters or updated fields"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # First, find the item
        response = table.scan(
            FilterExpression="customer_name = :customer_name AND provider = :provider AND userid = :userid",
            ExpressionAttributeValues={
                ":customer_name": customer_name,
                ":provider": provider,
                ":userid": userid
            }
        )

        items = response.get('Items', [])
        if not items:
            return jsonify({"error": "No matching record found to update"}), 404

        config_id = items[0]['config_id']

        # Update the item
        update_expression = "SET " + ", ".join([f"{k}=:{k}" for k in updated_fields.keys()])
        expression_attribute_values = {f":{k}": v for k, v in updated_fields.items()}

        table.update_item(
            Key={'config_id': config_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=convert_floats(expression_attribute_values)
        )

        return jsonify({"message": "Record updated successfully", "config_id": config_id}), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

@app.route('/api/delete_config', methods=['DELETE'])
def soft_delete_config():
    data = request.get_json()
    
    provider = data.get('provider')
    userid = data.get('userid')

    if not all([provider, userid]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find item
        response = table.scan(
            FilterExpression="provider = :provider AND userid = :userid",
            ExpressionAttributeValues={
                ":provider": provider,
                ":userid": userid
            }
        )

        items = response.get('Items', [])
        if not items:
            return jsonify({"error": "No matching record found to delete"}), 404

        config_id = items[0]['config_id']

        # Soft delete: Update flag
        table.update_item(
            Key={'config_id': config_id},
            UpdateExpression="SET is_deleted = :true",
            ExpressionAttributeValues={":true": True}
        )

        return jsonify({"message": "Record soft-deleted successfully", "config_id": config_id}), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

@app.route('/api/exit_all_users', methods=['POST'])
def exit_all_positions_and_orders():
    try:
        table = get_dynamo_table(TABLE_NAME)

        # Fetch all active user-provider configurations
        response = table.scan(
            FilterExpression="attribute_not_exists(is_deleted) OR is_deleted = :false",
            ExpressionAttributeValues={":false": False}
        )

        users = response.get('Items', [])

        if not users:
            return jsonify({"message": "No active users found."}), 404

        results = []

        # Placeholder logic: loop over each user and provider
        for user_record in users:
            user = user_record.get('userid')
            provider = user_record.get('provider')

            # Replace with real logic to exit positions and cancel GTT orders
            positions_exited = True  # placeholder
            orders_cancelled = True  # placeholder

            results.append({
                "user": user,
                "provider": provider,
                "positions_exited": positions_exited,
                "orders_cancelled": orders_cancelled
            })

        return jsonify({
            "message": "Exit and cancellation actions triggered for all users.",
            "details": results
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/restart_all_users', methods=['POST'])
def restart_all_users():
    try:
        table = get_dynamo_table(TABLE_NAME)

        # Fetch all active configurations
        response = table.scan(
            FilterExpression="attribute_not_exists(is_deleted) OR is_deleted = :false",
            ExpressionAttributeValues={":false": False}
        )

        users = response.get('Items', [])

        if not users:
            return jsonify({"message": "No active users found to restart."}), 404

        results = []

        # Restart action (trigger your main logic asynchronously)
        for user_config in users:
            run_main_async(user_config)  # Existing method to trigger main async process
            results.append({
                "user": user_config.get('userid'),
                "provider": user_config.get('provider'),
                "status": "Restart triggered"
            })

        return jsonify({
            "message": "Restart triggered successfully for all users.",
            "details": results
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
""" @app.route('/api/get_pnl', methods=['GET'])
def get_pnl():
    try:
        pnl_data = get_broker_pnl()
        return jsonify({
            "message": "Profit and Loss retrieved successfully",
            "pnl_data": pnl_data
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500 """
    

@app.route('/api/restart_user', methods=['POST'])
def restart_single_user():
    data = request.get_json()

    userid = data.get('userid')
    provider = data.get('provider')

    if not all([userid, provider]):
        return jsonify({"error": "Missing required parameters (userid, provider)"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find the user configuration in DynamoDB
        response = table.scan(
            FilterExpression="userid = :userid AND provider = :provider AND (attribute_not_exists(is_deleted) OR is_deleted = :false)",
            ExpressionAttributeValues={
                ":userid": userid,
                ":provider": provider,
                ":false": False
            }
        )

        items = response.get('Items', [])

        if not items:
            return jsonify({"error": "User configuration not found or is deleted."}), 404

        user_config = items[0]

        # Trigger the asynchronous restart (main logic)
        run_main_async(user_config)

        return jsonify({
            "message": f"Restart triggered successfully for user '{userid}' and provider '{provider}'."
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_user', methods=['POST'])
def stop_single_user():
    data = request.get_json()

    userid = data.get('userid')
    provider = data.get('provider')

    if not all([userid, provider]):
        return jsonify({"error": "Missing required parameters (userid, provider)"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Fetch the user configuration from DynamoDB
        response = table.scan(
            FilterExpression="userid = :userid AND provider = :provider AND (attribute_not_exists(is_deleted) OR is_deleted = :false)",
            ExpressionAttributeValues={
                ":userid": userid,
                ":provider": provider,
                ":false": False
            }
        )

        items = response.get('Items', [])

        if not items:
            return jsonify({"error": "User configuration not found or is already deleted."}), 404

        user_config = items[0]

        # Soft-stop logic (update 'is_running' or similar flag to False)
        table.update_item(
            Key={'config_id': user_config['config_id']},
            UpdateExpression="SET is_running = :false",
            ExpressionAttributeValues={":false": False}
        )

        return jsonify({
            "message": f"Operations stopped successfully for user '{userid}' and provider '{provider}'."
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
