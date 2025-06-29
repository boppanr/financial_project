from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
from dynamo_connection import convert_floats, get_dynamo_table, insert_config_data
import boto3
from botocore.exceptions import ClientError
import threading
from main import main
from datetime import datetime
#from oms import get_broker_pnl
from boto3.dynamodb.conditions import Attr, Key
import json
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer
import hashlib
import random

app = Flask(__name__)
CORS(app)
TABLE_NAME = "ConfigTable"
USERS_TABLE_NAME = "Users"
LOGIN_TABLE = "Login"

# User Management Functions
def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_user_data(data, is_update=False):
    """Validate user data"""
    required_fields = ['name', 'provider', 'user_id']
    if not is_update:
        required_fields.append('password')
    
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    # Validate provider
    valid_providers = ['Zerodha', 'Shoonya', 'Fyers', 'Groww', 'Dummy', 'Gopocket']
    if data['provider'] not in valid_providers:
        return False, f"Invalid provider. Must be one of: {', '.join(valid_providers)}"
    
    return True, "Valid"

def verify_user(username, password):
    """Verify user credentials against database"""
    try:
        table = get_dynamo_table(LOGIN_TABLE)
        
        # Hash the provided password to compare
        hashed_password = password
        
        # Get user by username (assuming username is stored as user_id or separate field)
        response = table.get_item(Key={'LoginId': username})
        
        if 'Item' not in response:
            return False, None
            
        user = response['Item']
        
        # Check if user is deleted
        if user.get('is_deleted', False):
            return False, None
            
        # Verify password
        if user.get('password') == hashed_password:
            # Return role if exists, default to 'user'
            role = user.get('role', 'user')
            return True, role
        else:
            return False, None
            
    except Exception as e:
        print(f"Error verifying user: {str(e)}")
        return False, None

def create_user_account(username, password, role='user'):
    """Create a new user account for login"""
    try:
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        # Check if user already exists
        try:
            existing_user = table.get_item(Key={'user_id': username})
            if 'Item' in existing_user and not existing_user['Item'].get('is_deleted', False):
                return False, 'User already exists'
        except:
            pass
            
        # Create user record for authentication
        user_data = {
            'user_id': username,
            'name': username,  # Default name to username
            'provider': 'System',  # System user for login
            'password': hash_password(password),
            'role': role,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'is_deleted': False
        }
        
        table.put_item(Item=user_data)
        return True, 'User created successfully'
        
    except Exception as e:
        return False, f'Error creating user: {str(e)}'

def get_user_pnl(user_id, provider):
    """Get P&L for a specific user and provider"""
    try:
        # This is a placeholder - you need to implement actual P&L retrieval
        # based on your broker API integration
        
        # For now, return mock data based on the dashboard example
        mock_data = {
            'FN107870': {'pnl': 70.80, 'pnl_percentage': 0.28},
            'SH123456': {'pnl': 150.80, 'pnl_percentage': 1.43},
            'FA411835': {'pnl': 270.80, 'pnl_percentage': 1.88},
            'FN124681': {'pnl': -10.10, 'pnl_percentage': -0.08},
            'FN124302': {'pnl': 134.80, 'pnl_percentage': 4.28},
            'FN116633': {'pnl': -234.53, 'pnl_percentage': -2.28},
            'FN123771': {'pnl': 332.13, 'pnl_percentage': 5.90}
        }
        
        if user_id in mock_data:
            return mock_data[user_id]
        else:
            # Return random mock data for other users
            mock_pnl = round(random.uniform(-500, 1000), 2)
            mock_percentage = round(random.uniform(-5, 10), 2)
            return {
                'pnl': mock_pnl,
                'pnl_percentage': mock_percentage
            }
        
        # TODO: Replace with actual broker API calls
        # if provider == 'Zerodha':
        #     return get_zerodha_pnl(user_id)
        # elif provider == 'Shoonya':
        #     return get_shoonya_pnl(user_id)
        # etc.
        
    except Exception as e:
        return {'pnl': 0.0, 'pnl_percentage': 0.0}

def run_main_async(config_data):
    thread = threading.Thread(target=main, args=(config_data,))
    thread.daemon = True  # Make thread a daemon so it doesn't prevent app shutdown
    thread.start()
    return thread

def find_matching_config(table, customer_name, provider, userid):
    """
    Helper function to find matching configuration based on customer_name, provider, and userid
    Returns (matching_config, config_id) or (None, None) if not found
    """
    response = table.scan(
        FilterExpression=(
            Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
        )
    )

    items = response.get('Items', [])

    for item in items:
        api_list = item.get('api', [])
        if not isinstance(api_list, list):
            continue

        for api_entry in api_list:
            if not isinstance(api_entry, dict):
                continue

            api_customer_name = api_entry.get('customer_name')
            api_provider = api_entry.get('provider')
            api_creds = api_entry.get('creds', {})
            if not isinstance(api_creds, dict):
                api_creds = {}

            api_userid = api_creds.get('userid') or api_creds.get('user_id')

            if (api_customer_name == customer_name and
                api_provider == provider and
                api_userid == userid):
                
                return item, item.get('config_id')
    
    return None, None

# User CRUD Operations

@app.route('/api/users', methods=['GET'])
def get_all_users():
    """Get all users with optional filtering"""
    try:
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        # Get filter parameter
        name_filter = request.args.get('name', '').strip()
        
        if name_filter:
            # Scan with filter
            response = table.scan(
                FilterExpression=Attr('name').contains(name_filter) & 
                                (Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False))
            )
        else:
            # Get all non-deleted users
            response = table.scan(
                FilterExpression=(
                    Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
                )
            )
        
        users = response.get('Items', [])
        
        # Format users for frontend (hide sensitive data)
        formatted_users = []
        for user in users:
            formatted_user = {
                'id': user.get('user_id'),
                'name': user.get('name'),
                'provider': user.get('provider'),
                'user_id': user.get('user_id'),
                'password': user.get('password'),  # Masked password
                'phone': user.get('phone'),
                'appCode': user.get('appCode'),
                'totp_secret': user.get('totp_secret'),
                'api_key': user.get('api_key', ''),
                'api_secret': user.get('api_secret'),  # Masked secret
                'created_at': user.get('created_at'),
                'updated_at': user.get('updated_at')
            }
            formatted_users.append(formatted_user)
        
        return jsonify({
            'success': True,
            'users': formatted_users,
            'count': len(formatted_users)
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Validate data
        is_valid, message = validate_user_data(data)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        # Check if user already exists
        try:
            existing_user = table.get_item(Key={'user_id': data['user_id']})
            if 'Item' in existing_user:
                return jsonify({
                    'success': False,
                    'error': 'User with this User ID already exists'
                }), 409
        except ClientError:
            pass  # User doesn't exist, which is what we want
        
        # Create user record
        user_data = {
            'userid': data['user_id'],
            'user_id': data['user_id'],
            'name': data['name'],
            'provider': data['provider'],
            'password': data['password'],
            'phone': data['phone'],
            'appCode': data['appCode'],
            'totp_secret': data['totp_secret'],
            'api_key': data.get('api_key', ''),
            'api_secret': data.get('api_secret', ''),
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'is_deleted': False
        }
        
        # Insert user
        table.put_item(Item=user_data)
        
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'user_id': data['user_id']
        }), 201
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user by ID"""
    try:
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        response = table.get_item(Key={'user_id': user_id})
        
        if 'Item' not in response:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        user = response['Item']
        
        # Check if user is deleted
        if user.get('is_deleted', False):
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Format user data (hide sensitive information)
        formatted_user = {
            'user_id': user['user_id'],
            'name': user['name'],
            'provider': user['provider'],
            'api_key': user.get('api_key', ''),
            'created_at': user.get('created_at'),
            'updated_at': user.get('updated_at')
        }
        
        return jsonify({
            'success': True,
            'user': formatted_user
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    """Update an existing user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        # Check if user exists
        #response = table.get_item(Key={'userid': user_id})
        response = table.query(
             KeyConditionExpression=Key('userid').eq(user_id)
            )
        if 'Items' not in response or response['Items'][0].get('is_deleted') == (True):
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Validate data (for update)
        is_valid, message = validate_user_data(data, is_update=True)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
        # Build update expression
        update_expression_parts = []
        expression_attribute_values = {}
        expression_attribute_names = {}
        
        # Update allowed fields
        updatable_fields = ['name', 'provider', 'api_key', 'api_secret', 'phone', 'totp_secret', 'appCode']
        
        for field in updatable_fields:
            if field in data:
                attr_name = f"#{field}"
                value_name = f":{field}"
                update_expression_parts.append(f"{attr_name} = {value_name}")
                expression_attribute_values[value_name] = data[field]
                expression_attribute_names[attr_name] = field
        
        # Handle password update separately
        if 'password' in data and data['password']:
            attr_name = "#password"
            value_name = ":password"
            update_expression_parts.append(f"{attr_name} = {value_name}")
            expression_attribute_values[value_name] = data['password']
            expression_attribute_names[attr_name] = 'password'
        
        # Always update the updated_at timestamp
        update_expression_parts.append("#updated_at = :updated_at")
        expression_attribute_values[":updated_at"] = datetime.utcnow().isoformat()
        expression_attribute_names["#updated_at"] = 'updated_at'
        
        if not update_expression_parts:
            return jsonify({
                'success': False,
                'error': 'No valid fields to update'
            }), 400
        
        update_expression = "SET " + ", ".join(update_expression_parts)
        
        # Perform update
        table.update_item(
            Key={'userid': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ExpressionAttributeNames=expression_attribute_names
        )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully',
            'user_id': user_id
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Soft delete a user"""
    try:
        table = get_dynamo_table(USERS_TABLE_NAME)
        
        # Check if user exists
        response = table.get_item(Key={'userid': user_id})
        if 'Item' not in response or response['Item'].get('is_deleted', True):
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Soft delete the user
        table.update_item(
            Key={'userid': user_id},
            UpdateExpression="SET is_deleted = :true, updated_at = :updated_at",
            ExpressionAttributeValues={
                ":true": True,
                ":updated_at": datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully',
            'user_id': user_id
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Dashboard specific endpoints
@app.route('/api/get_all_users_status', methods=['GET'])
def get_all_users_status():
    """Get all users with their trading status and P&L"""
    try:
        # Get configuration data
        config_table = get_dynamo_table(TABLE_NAME)
        config_response = config_table.scan(
            FilterExpression=(
                Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
            )
        )
        
        users_status = []
        counter = 1
        
        for config in config_response.get('Items', []):
            api_list = config.get('api', [])
            if not isinstance(api_list, list):
                continue
                
            for api_entry in api_list:
                if not isinstance(api_entry, dict):
                    continue
                    
                api_creds = api_entry.get('creds', {})
                if not isinstance(api_creds, dict):
                    api_creds = {}
                
                user_id = api_creds.get('userid') or api_creds.get('user_id')
                provider = api_entry.get('provider')
                customer_name = api_entry.get('customer_name')
                
                if user_id and provider and customer_name:
                    # Get P&L data
                    try:
                        pnl_data = get_user_pnl(user_id, provider)
                        pnl_value = pnl_data.get('pnl', 0.0)
                        pnl_percentage = pnl_data.get('pnl_percentage', 0.0)
                    except:
                        pnl_value = 0.0
                        pnl_percentage = 0.0
                    
                    # Determine status based on is_running flag
                    is_running = config.get('is_running', True)
                    status = 'active' if is_running else 'stopped'
                    
                    user_status = {
                        'id': counter,
                        'name': customer_name,
                        'provider': provider,
                        'user_id': user_id,
                        'status': status,
                        'pnl': pnl_value,
                        'pnl_percentage': pnl_percentage,
                        'config_id': config.get('config_id')
                    }
                    
                    users_status.append(user_status)
                    counter += 1
        
        return jsonify({
            'success': True,
            'users': users_status
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/exit_user', methods=['POST'])
def exit_single_user():
    """Exit all positions for a single user"""
    try:
        data = request.get_json()
        
        customer_name = data.get('customer_name')
        userid = data.get('userid')
        provider = data.get('provider')
        
        if not all([customer_name, userid, provider]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            }), 400
        
        table = get_dynamo_table(TABLE_NAME)
        
        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)
        
        if not matching_config:
            return jsonify({
                'success': False,
                'error': 'User configuration not found'
            }), 404
        
        # TODO: Implement actual exit logic based on provider
        # This is where you would call your broker-specific exit functions
        
        # For now, just return success
        # exit_success = exit_positions_for_user(userid, provider)
        exit_success = True  # Placeholder
        
        if exit_success:
            return jsonify({
                'success': True,
                'message': f'Successfully exited all positions for {customer_name}'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to exit positions'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/get_user_details/<user_id>', methods=['GET'])
def get_user_details_by_id(user_id):
    """Get detailed user information including configuration"""
    try:
        # Get user from users table
        users_table = get_dynamo_table(USERS_TABLE_NAME)
        user_response = users_table.get_item(Key={'user_id': user_id})
        
        if 'Item' not in user_response:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        user = user_response['Item']
        
        # Get configuration data
        config_table = get_dynamo_table(TABLE_NAME)
        config_response = config_table.scan(
            FilterExpression=(
                Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
            )
        )
        
        # Find matching configurations
        user_configs = []
        for config in config_response.get('Items', []):
            api_list = config.get('api', [])
            for api_entry in api_list:
                if isinstance(api_entry, dict):
                    api_creds = api_entry.get('creds', {})
                    config_user_id = api_creds.get('userid') or api_creds.get('user_id')
                    if config_user_id == user_id:
                        user_configs.append(config)
                        break
        
        return jsonify({
            'success': True,
            'user': user,
            'configurations': user_configs
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/update_user_status', methods=['POST'])
def update_user_status():
    """Update user running status"""
    try:
        data = request.get_json()
        
        customer_name = data.get('customer_name')
        userid = data.get('userid')
        provider = data.get('provider')
        status = data.get('status')  # 'active' or 'stopped'
        
        if not all([customer_name, userid, provider, status]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            }), 400
        
        table = get_dynamo_table(TABLE_NAME)
        
        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)
        
        if not matching_config:
            return jsonify({
                'success': False,
                'error': 'User configuration not found'
            }), 404
        
        # Update status
        is_running = status == 'active'
        
        table.update_item(
            Key={'config_id': matching_config_id},
            UpdateExpression="SET is_running = :status, updated_at = :updated_at",
            ExpressionAttributeValues={
                ':status': is_running,
                ':updated_at': datetime.utcnow().isoformat()
            }
        )
        
        return jsonify({
            'success': True,
            'message': f'User status updated to {status}'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/get_user_pnl/<user_id>/<provider>', methods=['GET'])
def get_individual_user_pnl(user_id, provider):
    """Get P&L for a specific user and provider"""
    try:
        pnl_data = get_user_pnl(user_id, provider)
        return jsonify({
            'success': True,
            'pnl_data': pnl_data
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Existing configuration management endpoints

@app.route('/api/submit_json', methods=['POST'])
def submit_json_to_db():
    config_data = request.get_json()
    
    if not config_data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    config_data.setdefault('config_id', str(uuid.uuid4()))
    config_data['creation_time'] = datetime.utcnow().isoformat()

    try:
        # First, store the configuration in the database
        table = get_dynamo_table(TABLE_NAME)
        insert_config_data(table, config_data)
        
        # Then, trigger the main trading logic asynchronously with config_data
        thread = run_main_async(config_data)
        
        return jsonify({
            "message": "Configuration submitted successfully and trading started",
            "config_id": config_data['config_id'],
            "status": "Trading process initiated"
        }), 201
        
    except Exception as e:
        return jsonify({
            "error": f"Failed to submit configuration: {str(e)}"
        }), 500

@app.route('/api/get_config_by_details', methods=['GET'])
def get_config_by_details():
    customer_name = request.args.get('customer_name')
    provider = request.args.get('provider')
    userid = request.args.get('userid')
    executionDay = request.args.get('execution_day')

    if not all([customer_name, provider, userid, executionDay]):
        return jsonify({"error": "Missing required query parameters"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Scan only records where is_deleted is not true (either missing or False)
        response = table.scan(
            FilterExpression=(
                (Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)) &
                (Attr('schedule.execution_days').exists() & Attr('schedule.execution_days').eq(executionDay))
            )
        )

        items = response.get('Items', [])

        matching_records = []

        for item in items:
            api_list = item.get('api', [])
            # Guard: ensure api_list is a list
            if not isinstance(api_list, list):
                continue

            for api_entry in api_list:
                if not isinstance(api_entry, dict):
                    # skip malformed entries
                    continue

                api_customer_name = api_entry.get('customer_name')
                api_provider = api_entry.get('provider')
                api_creds = api_entry.get('creds', {})
                if not isinstance(api_creds, dict):
                    api_creds = {}

                api_userid = api_creds.get('userid') or api_creds.get('user_id')

                if (api_customer_name == customer_name and
                    api_provider == provider and
                    api_userid == userid):
                    
                    # Create a comprehensive record that includes both API and strategy details
                    complete_record = {
                        'config_id': item.get('config_id'),
                        'creation_time': item.get('creation_time'),
                        'api': api_list,
                        'strategy': item.get('strategy', {}),
                        'instruments': item.get('instruments', []),
                        'risk_management': item.get('risk_management', {}),
                        'execution_settings': item.get('execution_settings', {}),
                        'notifications': item.get('notifications', {}),
                        'schedule': item.get('schedule', {}),
                        'is_running': item.get('is_running', False),
                        # Include any other fields that might be relevant
                        'full_config': {k: v for k, v in item.items() if k not in ['api']}
                    }
                    
                    matching_records.append(complete_record)

        if not matching_records:
            return jsonify({"error": "No matching active records found"}), 404

        return jsonify(matching_records), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

@app.route('/api/update_config', methods=['PUT'])
def update_config_by_details():
    config_data = request.get_json()
    
    if not config_data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    # Extract identification parameters from the config_data
    # These should be present in the API section of the config
    customer_name = None
    provider = None
    userid = None
    
    # Extract from the api section of config_data
    api_list = config_data.get('api', [])
    if api_list and isinstance(api_list, list) and len(api_list) > 0:
        api_entry = api_list[0]  # Assuming first entry for identification
        if isinstance(api_entry, dict):
            customer_name = api_entry.get('customer_name')
            provider = api_entry.get('provider')
            api_creds = api_entry.get('creds', {})
            if isinstance(api_creds, dict):
                userid = api_creds.get('userid') or api_creds.get('user_id')
    
    # Alternative: Accept identification parameters separately if not in config_data
    if not all([customer_name, provider, userid]):
        customer_name = config_data.get('customer_name')
        provider = config_data.get('provider')
        userid = config_data.get('userid')
    
    if not all([customer_name, provider, userid]):
        return jsonify({"error": "Missing required identification parameters (customer_name, provider, userid)"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)

        if not matching_config:
            return jsonify({"error": "No matching record found to update"}), 404

        # Preserve the original config_id and creation_time
        original_config_id = matching_config.get('config_id')
        original_creation_time = matching_config.get('creation_time')
        
        # Update the config_data with preserved values
        config_data['config_id'] = original_config_id
        if original_creation_time:
            config_data['creation_time'] = original_creation_time
        
        # Add/update the last_modified timestamp
        config_data['last_modified'] = datetime.utcnow().isoformat()
        
        # Convert any float values for DynamoDB compatibility
        config_data = convert_floats(config_data)
        
        # Replace the entire record (except for the key)
        # Build update expression for all fields except config_id
        update_expression_parts = []
        expression_attribute_values = {}
        expression_attribute_names = {}
        
        for key, value in config_data.items():
            if key != 'config_id':  # Don't update the primary key
                attr_name = f"#{key}"
                value_name = f":{key}"
                update_expression_parts.append(f"{attr_name} = {value_name}")
                expression_attribute_values[value_name] = value
                expression_attribute_names[attr_name] = key

        if not update_expression_parts:
            return jsonify({"error": "No valid fields to update"}), 400

        update_expression = "SET " + ", ".join(update_expression_parts)

        # Perform the update
        update_params = {
            'Key': {'config_id': original_config_id},
            'UpdateExpression': update_expression,
            'ExpressionAttributeValues': expression_attribute_values,
            'ExpressionAttributeNames': expression_attribute_names
        }

        table.update_item(**update_params)

        return jsonify({
            "message": "Configuration updated successfully",
            "config_id": original_config_id,
            "customer_name": customer_name,
            "provider": provider,
            "userid": userid
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": f"Update failed: {str(e)}"}), 500

@app.route('/api/delete_config', methods=['DELETE'])
def soft_delete_config():
    data = request.get_json()
    
    customer_name = data.get('customer_name')
    provider = data.get('provider')
    userid = data.get('userid')

    print(data)
    if not all([customer_name, provider, userid]):
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)

        if not matching_config:
            return jsonify({"error": "No matching record found to delete"}), 404

        # Soft delete: Update flag
        table.update_item(
            Key={'config_id': matching_config_id},
            UpdateExpression="SET is_deleted = :true",
            ExpressionAttributeValues={":true": True}
        )

        return jsonify({"message": "Record soft-deleted successfully", "config_id": matching_config_id}), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500

@app.route('/api/exit_all_users', methods=['POST'])
def exit_all_positions_and_orders():
    try:
        table = get_dynamo_table(TABLE_NAME)

        today = datetime.today().strftime('%d/%m/%Y')
        # Fetch all active user-provider configurations
        response = table.scan(
            FilterExpression=(
                (Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)) &
                (Attr('schedule.execution_days').exists() & Attr('schedule.execution_days').eq(today))
            )
        )
        
        users = response.get('Items', [])

        if not users:
            return jsonify({"message": "No active users found."}), 404

        results = []

        # Loop over each user configuration and extract user details from API entries
        for user_record in users:
            api_list = user_record.get('api', [])
            if not isinstance(api_list, list):
                continue

            for api_entry in api_list:
                if not isinstance(api_entry, dict):
                    continue

                api_creds = api_entry.get('creds', {})
                if not isinstance(api_creds, dict):
                    api_creds = {}

                user = api_creds.get('userid') or api_creds.get('user_id')
                provider = api_entry.get('provider')
                customer_name = api_entry.get('customer_name')

                if user and provider:
                    # Replace with real logic to exit positions and cancel GTT orders
                    positions_exited = True  # placeholder
                    orders_cancelled = True  # placeholder

                    results.append({
                        "customer_name": customer_name,
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

        today = datetime.today().strftime('%d/%m/%Y')
        # Fetch all active user-provider configurations
        response = table.scan(
            FilterExpression=(
                (Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)) &
                (Attr('schedule.execution_days').exists() & Attr('schedule.execution_days').eq(today))
            )
        )

        users = response.get('Items', [])

        if not users:
            return jsonify({"message": "No active users found to restart."}), 404

        results = []

        # Restart action (trigger your main logic asynchronously)
        for user_config in users:
            api_list = user_config.get('api', [])
            if not isinstance(api_list, list):
                continue

            for api_entry in api_list:
                if not isinstance(api_entry, dict):
                    continue

                api_creds = api_entry.get('creds', {})
                if not isinstance(api_creds, dict):
                    api_creds = {}

                user = api_creds.get('userid') or api_creds.get('user_id')
                provider = api_entry.get('provider')
                customer_name = api_entry.get('customer_name')

                if user and provider:
                    thread = run_main_async(user_config)  # Pass config to main async process
                    results.append({
                        "customer_name": customer_name,
                        "user": user,
                        "provider": provider,
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

    customer_name = data.get('customer_name')
    userid = data.get('userid')
    provider = data.get('provider')

    if not all([customer_name, userid, provider]):
        return jsonify({"error": "Missing required parameters (customer_name, userid, provider)"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)

        if not matching_config:
            return jsonify({"error": "User configuration not found or is deleted."}), 404

        # Trigger the asynchronous restart (main logic) with config data
        thread = run_main_async(matching_config)

        return jsonify({
            "message": f"Restart triggered successfully for user '{userid}' with provider '{provider}' and customer '{customer_name}'."
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_user', methods=['POST'])
def stop_single_user():
    data = request.get_json()

    customer_name = data.get('customer_name')
    userid = data.get('userid')
    provider = data.get('provider')

    if not all([customer_name, userid, provider]):
        return jsonify({"error": "Missing required parameters (customer_name, userid, provider)"}), 400

    try:
        table = get_dynamo_table(TABLE_NAME)

        # Find the matching configuration
        matching_config, matching_config_id = find_matching_config(table, customer_name, provider, userid)

        if not matching_config:
            return jsonify({"error": "User configuration not found or is already deleted."}), 404

        # Soft-stop logic (update 'is_running' or similar flag to False)
        table.update_item(
            Key={'config_id': matching_config_id},
            UpdateExpression="SET is_running = :false",
            ExpressionAttributeValues={":false": False}
        )

        return jsonify({
            "message": f"Operations stopped successfully for user '{userid}' with provider '{provider}' and customer '{customer_name}'."
        }), 200

    except ClientError as e:
        return jsonify({"error": e.response['Error']['Message']}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing credentials'}), 400

    is_valid, role = verify_user(username, password)
    if is_valid:
        return jsonify({'message': 'Login successful', 'role': role}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # Default role is 'user' if not provided

    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    success, msg = create_user_account(username, password, role)
    status = 201 if success else 409
    return jsonify({'message': msg}), status

@app.route('/api/get_configs_by_execution_day', methods=['GET'])
def get_configs_by_execution_day():
    """Get all configuration JSONs based on target execution day"""
    try:
        # Get the target execution day from query parameters
        target_day = request.args.get('target_day')
        
        if not target_day:
            return jsonify({
                'success': False,
                'error': 'target_day parameter is required'
            }), 400
        
        table = get_dynamo_table(TABLE_NAME)
        
        # Scan all non-deleted configurations
        response = table.scan(
            FilterExpression=(
                Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
            )
        )
        
        configs = response.get('Items', [])
        matching_configs = []
        
        for config in configs:
            # Check if schedule exists and has execution days
            schedule = config.get('schedule', {})
            execution_days = schedule.get('execution_days', [])
            
            # Handle different formats of execution days
            if isinstance(execution_days, list):
                # Check if target_day is in the list (case-insensitive)
                if any(day.lower() == target_day.lower() for day in execution_days if isinstance(day, str)):
                    matching_configs.append(config)
            elif isinstance(execution_days, str):
                # If execution_days is a single string
                if execution_days.lower() == target_day.lower():
                    matching_configs.append(config)
        
        return jsonify({
            'success': True,
            'configs': matching_configs,
            'count': len(matching_configs),
            'target_day': target_day
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/get_configs_by_execution_days', methods=['POST'])
def get_configs_by_multiple_execution_days():
    """Get all configuration JSONs based on multiple target execution days"""
    try:
        data = request.get_json()
        
        if not data or 'target_days' not in data:
            return jsonify({
                'success': False,
                'error': 'target_days array is required in request body'
            }), 400
        
        target_days = data.get('target_days', [])
        
        if not isinstance(target_days, list) or not target_days:
            return jsonify({
                'success': False,
                'error': 'target_days must be a non-empty array'
            }), 400
        
        table = get_dynamo_table(TABLE_NAME)
        
        # Scan all non-deleted configurations
        response = table.scan(
            FilterExpression=(
                Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
            )
        )
        
        configs = response.get('Items', [])
        matching_configs = []
        
        # Convert target_days to lowercase for case-insensitive comparison
        target_days_lower = [day.lower() for day in target_days]
        
        for config in configs:
            # Check if schedule exists and has execution days
            schedule = config.get('schedule', {})
            execution_days = schedule.get('execution_days', [])
            
            config_matches = False
            
            # Handle different formats of execution days
            if isinstance(execution_days, list):
                # Check if any target_day is in the config's execution_days
                for exec_day in execution_days:
                    if isinstance(exec_day, str) and exec_day.lower() in target_days_lower:
                        config_matches = True
                        break
            elif isinstance(execution_days, str):
                # If execution_days is a single string
                if execution_days.lower() in target_days_lower:
                    config_matches = True
            
            if config_matches:
                matching_configs.append(config)
        
        return jsonify({
            'success': True,
            'configs': matching_configs,
            'count': len(matching_configs),
            'target_days': target_days
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/get_all_execution_days', methods=['GET'])
def get_all_execution_days():
    """Get all unique execution days from all configurations"""
    try:
        table = get_dynamo_table(TABLE_NAME)
        
        # Scan all non-deleted configurations
        response = table.scan(
            FilterExpression=(
                Attr('is_deleted').not_exists() | Attr('is_deleted').eq(False)
            )
        )
        
        configs = response.get('Items', [])
        all_execution_days = set()
        
        for config in configs:
            schedule = config.get('schedule', {})
            execution_days = schedule.get('execution_days', [])
            
            if isinstance(execution_days, list):
                for day in execution_days:
                    if isinstance(day, str):
                        all_execution_days.add(day.lower().capitalize())
            elif isinstance(execution_days, str):
                all_execution_days.add(execution_days.lower().capitalize())
        
        return jsonify({
            'success': True,
            'execution_days': sorted(list(all_execution_days)),
            'count': len(all_execution_days)
        }), 200
        
    except ClientError as e:
        return jsonify({
            'success': False,
            'error': e.response['Error']['Message']
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)