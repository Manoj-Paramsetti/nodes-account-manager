import boto3

client = boto3.client('dynamodb', region_name='localhost', endpoint_url="http://localhost:8000", aws_access_key_id="dummy", aws_secret_access_key="dummy")
dynamodb = boto3.resource('dynamodb', region_name='localhost', endpoint_url="http://localhost:8000", aws_access_key_id="dummy", aws_secret_access_key="dummy")