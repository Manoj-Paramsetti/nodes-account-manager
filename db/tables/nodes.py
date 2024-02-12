# From the __init__ importing the dynamodb and client connectors.
from db import dynamodb, client


# Function to initialise bastion_nodes table in the mentioned region in the config.
def init():
    
    ## Checking the table existence in the cloud.
    response = client.list_tables()
    if "bastion_nodes" in response["TableNames"]:
        return
    
    ## If the table not found the create the table with the mentioned partition key and the sort key.
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
    # Pause the script until creation of table.
    table.wait_until_exists()