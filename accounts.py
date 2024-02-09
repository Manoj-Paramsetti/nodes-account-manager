import sys
import os
import time
import re
import requests
import json

from colorama import Fore, Back, Style
from db import dynamodb
from db.tables.accounts import init as accounts_init
from db.tables.nodes import init as nodes_init

clear = lambda: os.system('clear')

Accounts = dynamodb.Table("bastion_accounts")
Nodes = dynamodb.Table("bastion_nodes")

def init():
    clear()
    accounts_init()
    nodes_init()
    document = requests.request(url="http://169.254.169.254/latest/dynamic/instance-identity/document", method="get")
    ipv4 = requests.request(url="http://169.254.169.254/latest/meta-data/public-ipv4", method="get")
    username = os.popen("whoami").read().replace('\n', '')
    if document.status_code == 200:
        node_info = json.loads(document.text)
        
        Nodes.put_item(
            Item = {
                "node_type": "bastion",
                "region": node_info["region"],
                "ipv4": ipv4,
                "name": f'{node_info["instanceId"]}-{node_info["instanceType"]}',
                "username": username
            }
        )

if len(sys.argv) == 2 and "init" in sys.argv:
    init()
    exit()


def custom_input(prompt=""):
    return input("\n" + Back.GREEN + prompt + " > " + Style.RESET_ALL + " ")

def add_user_with_replicas(username, _ssh_key):
    Accounts.put_item(
        Item = {
            "user_group": "non-sudoer",
            "created_at": time.time_ns(),
            "username": username,
            "sshkey": _ssh_key,
            "target": "*"
        }
    )

def add_user_in_targeted(username, _ssh_key, target):
    Accounts.put_item(
        Item = {
            "user_group": "non-sudoer",
            "created_at": time.time_ns(),
            "username": username,
            "sshkey": _ssh_key,
            "target": target["ipv4"]
        }
    )

def add_node_in_db(ipv4, name, username):
    Nodes.put_item(
        Item = {
            "node_type": "bastion",
            "created_at": time.time_ns(),
            "ipv4": ipv4,
            "name": name,
            "username": username
        }
    )

def update_ssh_key(item):
    try:
       new_ssh = custom_input("New SSH")
       Accounts.update_item(
           Key={
                "user_group": item["user_group"],
                "created_at": item["created_at"]
            },
            UpdateExpression="set #s = :s",
            ExpressionAttributeNames={
                "#s": "sshkey"
            },
            ExpressionAttributeValues={
                ":s": new_ssh
            }
       )
       return new_ssh
    except:
        print("Wrong ID. Try again")
        custom_input()
        modify_user_handler()

def delete_user(item):
    try:
        Accounts.delete_item(
            Key={
                "user_group": item["user_group"],
                "created_at": item["created_at"]
            }
        )
    except:
        print("Wrong ID. Try again")
        custom_input()
        delete_user_handler()

def delete_node(item):
    try:
        Nodes.delete_item(
            Key={
                "node_type": item["node_type"],
                "created_at": item["created_at"]
            }
        )
        delete_user_specified_node(item['ipv4'])
    except:
        print("Wrong ID. Try again")
        custom_input()
        delete_user_handler()

def delete_user_specified_node(IPV4):
    try:
        accounts = Accounts.scan()
        for account in accounts["Items"]:
            if(account["target"] == IPV4):
                Accounts.delete_item(
                    Key={
                        "user_group": account['user_group'],
                        "created_at": account['created_at']
                    }
                )
    except:
        print("Wrong ID. Try again")
        custom_input()
        delete_user_handler()    

def list_users():
    clear()
    all_accounts = Accounts.scan()
    i = 1
    for account in all_accounts["Items"]:
        print(i, account["user_group"], account["username"], account["target"])
        i+=1
    return all_accounts["Items"]
    
def list_nodes():
    clear()
    all_node = Nodes.scan()
    i = 1
    for account in all_node["Items"]:
        print(i, account["node_type"], account["ipv4"])
        i+=1
    return all_node["Items"]

def modify_user_handler():
    accounts =  list_users()

    id = custom_input("Pass the ID to select")   
    selected_account =  accounts[int(id)-1]
    sshkey = update_ssh_key(selected_account)

    username = selected_account["username"]
    if selected_account["target"] == "*":
        nodes = list_nodes()
        for node in nodes:
            os.system(f'ssh {node["username"]}@{node["ipv4"]} \'echo "{sshkey}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
    else:
        os.system(f'ssh ec2-user@{selected_account["target"]} \'echo "{sshkey}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
    custom_input("Completed!")

def delete_user_handler():
    accounts = list_users()
    id = custom_input()
    selected_account =  accounts[int(id)-1]
    delete_user(accounts[int(id)-1])
    username = selected_account["username"]
    if selected_account["target"] == "*":
        nodes = list_nodes()
        for node in nodes:
            os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo userdel -r {username}')
    else:
        os.system(f'ssh ec2-user@{selected_account["target"]} sudo userdel -r {username}')       

def delete_node_handler():
    node = list_nodes()
    print("\n🔴 This will delete records from the accounts. If accounts are needed in future. Replace it with the another node")
    id = custom_input()
    delete_node(node[int(id)-1])

def clone_node():
    accounts = Accounts.scan()
    nodes = list_nodes()

    selected_node_id = custom_input("Select Node ID to replica")
    selected_target_id = custom_input("Select Target Node ID")
    selected_node = nodes[int(selected_node_id)-1]
    selected_target = nodes[int(selected_target_id)-1]
    for account in accounts["Items"]:
        if(account["target"] == selected_node["ipv4"]):
            add_user_in_targeted(account['username'], account['sshkey'], selected_target)

def user_nav_options(user_input):
    if user_input == "1":
        clear()
        username = custom_input("Username")
        ssh_key = custom_input("SSH Key")
        add_user_with_replicas(username, ssh_key)
        nodes = list_nodes()
        for node in nodes:
            try:
                print(node["ipv4"], end="")
                os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo useradd -m {username}')
                os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo -u {username} mkdir -p /home/{username}/.ssh')
                os.system(f'ssh {node["username"]}@{node["ipv4"]} \'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
            except:
                print(f'Failed sync in {node["ipv4"]}')
        custom_input("Completed!")
    elif user_input == "2":
        clear()
        username = custom_input("Username")
        ssh_key = custom_input("SSH Key")
        clear()
        nodes = list_nodes()
        id = custom_input("ID")
        selected_node = nodes[int(id)-1]
        add_user_in_targeted(username, ssh_key, selected_node)
        os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo useradd -m {username}')
        os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo -u {username} mkdir -p /home/{username}/.ssh')
        os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} \'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
        custom_input("Completed!")
    elif user_input == "3":
        list_users()
        custom_input()
        manage_users()
    elif user_input == "4":
        modify_user_handler()
    elif user_input == "5":
        delete_user_handler()
    elif user_input == "6":
        welcome_screen()
    else:
        custom_input("Wrong Input")
        manage_users()

def node_nav_options(user_input):
    if user_input == "1":
        clear()
        ipv4 = custom_input("IPV4")
        name = custom_input("Node Name")
        username = custom_input("Username for SSH")
        add_node_in_db(ipv4, name, username)
    elif user_input == "2":
        list_nodes()
        custom_input()
        manage_nodes()
    elif user_input == "3":
        # Sync
        pass
    elif user_input == "4":
        delete_node_handler()
    elif user_input == "5":
        clone_node()
    elif user_input == "6":
        welcome_screen()
    else:
        custom_input("Wrong Input")
        manage_nodes()

def manage_users():
    clear()
    print("1. Add User with Replication")
    print("2. Add User in Single Node")
    print("3. List User")
    print("4. Modify Key")
    print("5. Delete User")
    print("6. Go back to Home")

    user_input = custom_input()
    user_nav_options(user_input)

def manage_nodes():
    clear()
    print("1. Add Nodes")
    print("2. List Nodes")
    print("3. Sync Node")
    print("4. Delete Node")
    print("5. Replica Node Accounts (Not Synchronizable in Nodes)")
    print("6. Go back to Home")

    user_input = custom_input()
    node_nav_options(user_input)

def nav_options(user_input):
    if user_input == "1":
        init()
    elif user_input == "2":
        manage_nodes()
    elif user_input == "3":
        manage_users()
    else:
        custom_input("Wrong Input")
        welcome_screen()
        
def welcome_screen():
    clear()
    print("Accounts Manager")
    print("1. Init DB")
    print("2. Manage Nodes")
    print("3. Manage Users")

    user_input = custom_input()

    nav_options(user_input)

if __name__ == "__main__":
    welcome_screen()