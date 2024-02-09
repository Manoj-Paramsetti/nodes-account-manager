from db import dynamodb, client

def init():
    response = client.list_tables()
    if "bastion_nodes" in response["TableNames"]:
        return
        
    table = dynamodb.create_table(
        TableName='bastion_nodes',
        KeySchema=[
            {
                'AttributeName': 'node_type',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'region',
                'KeyType': 'SORT'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'node_type',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'region',
                'AttributeType': 'S'
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    table.wait_until_exists()