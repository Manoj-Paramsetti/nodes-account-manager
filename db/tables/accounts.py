from db import dynamodb, client

def init():
    response = client.list_tables()
    if "bastion_accounts" in response["TableNames"]:
        return
        
    table = dynamodb.create_table(
        TableName='bastion_accounts',
        KeySchema=[
            {
                'AttributeName': 'user_group',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'created_at',
                'KeyType': 'SORT'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'user_group',
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