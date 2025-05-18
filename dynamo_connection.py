import boto3

def get_dynamo_table(table_name, region="us-east-1"):
    dynamodb = boto3.resource("dynamodb", region_name=region)
    return dynamodb.Table(table_name)

def insert_config_data(table, data):
    response = table.put_item(Item=data)
    return response
