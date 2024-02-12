# Importing boto3 module for dynamodb connection
import boto3

# Change the region based on dynamodb deployment
client = boto3.client('dynamodb', region_name='us-east-1')
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')