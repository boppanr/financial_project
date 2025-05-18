import boto3
from decimal import Decimal

def convert_floats(obj):
    if isinstance(obj, list):
        return [convert_floats(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_floats(v) for k, v in obj.items()}
    elif isinstance(obj, float):
        return Decimal(str(obj))  # precise conversion
    else:
        return obj

def get_dynamo_table(table_name, region="us-east-1"):
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(table_name)

def insert_config_data(table, data):
    data = convert_floats(data)  # Convert all floats to Decimals
    response = table.put_item(Item=data)
    return response

