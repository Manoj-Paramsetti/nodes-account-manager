import boto3

client = boto3.client('dynamodb', region_name='us-east-1')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')