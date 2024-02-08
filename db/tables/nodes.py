from db import dynamodb, client

def init():
    response = client.list_tables()
    if "nodes" in response["TableNames"]:
        return
        
    table = dynamodb.create_table(
        TableName='nodes',
        KeySchema=[
            {
                'AttributeName': 'node_type',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'created_at',
                'KeyType': 'SORT'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'node_type',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'created_at',
                'AttributeType': 'N'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    table.wait_until_exists()