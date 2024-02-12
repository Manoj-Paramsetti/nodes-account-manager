# From the __init__ importing the dynamodb and client connectors.
from db import dynamodb, client

# Function to initialise bastion_nodes table in the mentioned region in the config.
def init():

    ## Checking the table existence in the cloud.
    response = client.list_tables()
    if "bastion_accounts" in response["TableNames"]:
        return
    
    ## If the table not found the create the table with the mentioned partition key and the sort key.    
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
    ## Pause the script until creation of table.
    table.wait_until_exists()