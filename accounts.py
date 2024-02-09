import sys
import os
import time
import requests
import json
import re

from colorama import Back, Style
from db import dynamodb
from db.tables.accounts import init as accounts_init
from db.tables.nodes import init as nodes_init

try:
    clear = lambda: os.system('clear')

    Accounts = dynamodb.Table("bastion_accounts")
    Nodes = dynamodb.Table("bastion_nodes")

    document = requests.request(url="http://169.254.169.254/latest/dynamic/instance-identity/document", method="get")
    node_info = json.loads(document.text)

    exit_commands = ["q", "exit", "quit"]
    
    def clean_comments(groups):
        data = list(groups)
        for line in data:
            match = re.match("^[\s]*#", line)
            if match or line == '':
                groups.remove(line)
        return sorted(groups)
    
    def get_user_list(host_user=None, ip=None, no_ssh = False):
        if no_ssh:
            users = os.popen("cat /etc/passwd | awk -F: '{ print $1 }'").read().split('\n')
            return clean_comments(users)   
        users = os.popen(f'ssh {host_user}@{ip}' + ' ' + '\'cat /etc/passwd | awk -F: "{ print $1 }"\'')
        return clean_comments(users)
        
    def init():
        clear()
        accounts_init()
        nodes_init()
        ipv4 = requests.request(url="http://169.254.169.254/latest/meta-data/public-ipv4", method="get")
        username = os.popen("whoami").read().replace('\n', '')
        if document.status_code == 200:
            Nodes.put_item(
                Item = {
                    "node_type": "bastion",
                    "region": node_info["region"],
                    "ipv4": ipv4.text,
                    "name": f'{node_info["instanceId"]}-{node_info["instanceType"]}',
                    "username": username
                }
            )
            accounts = Accounts.scan()["Items"]
            users_list = get_user_list(no_ssh=True)
            for account in accounts:
                if account["target"] in ["*", node_info["region"]]:
                    if (account["username"] not in users_list):
                        os.system(f'sudo useradd -m {account["username"]}')
                        os.system(f'sudo -u {account["username"]} mkdir -p /home/{account["username"]}/.ssh')
                    else:
                        print("\n" + Back.GREEN + "Overwriting SSH key on", account["username"] + Style.RESET_ALL + " ")
                    os.system(f'echo "{account["sshkey"]}" | sudo -u {account["username"]} tee /home/{account["username"]}/.ssh/authorized_keys >/dev/null')

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
                "target": target["region"]
            }
        )

    def add_node_in_db(ipv4, name, username):
        Nodes.put_item(
            Item = {
                "node_type": "bastion",
                "region": time.time_ns(),
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
                    "region": item["region"]
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
        for node in all_node["Items"]:
            print(i, node["node_type"], node["ipv4"], node["region"])
            i+=1
        return all_node["Items"]

    def modify_user_handler():
        accounts =  list_users()

        id = custom_input("Pass the ID to select")
        try:   
            selected_account =  accounts[int(id)-1]
        except(IndexError, ValueError):
            custom_input("Invalid ID")
            manage_users()
            return
        sshkey = update_ssh_key(selected_account)

        username = selected_account["username"]
        if selected_account["target"] == "*":
            nodes = list_nodes()
            for node in nodes:
                os.system(f'ssh {node["username"]}@{node["ipv4"]} \'echo "{sshkey}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
        else:
            nodes = list_nodes()
            clear()
            selected_node = {}
            for i in nodes:
                if(selected_account["target"] == i["region"]):
                    selected_node = i["region"]
            os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} \'echo "{sshkey}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
        custom_input("Completed!")

    def delete_user_handler():
        accounts = list_users()
        id = custom_input()
        try:
            selected_account =  accounts[int(id)-1]
        except(IndexError, ValueError):
            custom_input("Invalid ID")
            manage_users()
            return
        delete_user(selected_account)
        username = selected_account["username"]
        if selected_account["target"] == "*":
            nodes = list_nodes()
            for node in nodes:
                os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo userdel -rf {username}')
        else:
            nodes = list_nodes()
            clear()
            selected_node = {}
            for i in nodes:
                if(selected_account["target"] == i["region"]):
                    selected_node = i["region"]
            os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo userdel -rf {username}')       

    def sync_node_handler():
        nodes = list_nodes()
        ID = custom_input("Select the node by ID")
        try:
            selected_node = nodes[int(ID)-1]
        except(IndexError, ValueError):
            custom_input("Invalid ID")
            manage_nodes()
            return
        accounts  = list_users()
        clear()
        user_list = []
        if selected_node["region"] != node_info["region"]:
            user_list = get_user_list(selected_node["username"], selected_node["ipv4"])
        else:
            user_list = get_user_list(no_ssh=True)
        for account in accounts:
            if account["target"] in ["*", selected_node["region"]]:
                print(f'Adding account: {account["username"]}')
                if selected_node["region"] != node_info["region"]:
                    if account["username"] not in user_list:
                        os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo useradd -m {account["username"]}')
                        os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo -u {account["username"]} mkdir -p /home/{account["username"]}/.ssh')
                    else:
                        print("\n" + Back.GREEN + "User already exists! Overwriting Keys" + Style.RESET_ALL + " ")
                    os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} \'echo "{account["sshkey"]}" | sudo -u {account["username"]} tee /home/{account["username"]}/.ssh/authorized_keys >/dev/null\'')
                else:
                    if account["username"] not in user_list:
                        os.system(f'sudo useradd -m {account["username"]}')
                        os.system(f'sudo -u {account["username"]} mkdir -p /home/{account["username"]}/.ssh')
                    else:
                        print("\n" + Back.GREEN + "User already exists! Overwriting Keys" + Style.RESET_ALL + " ")
                    os.system(f'echo "{account["sshkey"]}" | sudo -u {account["username"]} tee /home/{account["username"]}/.ssh/authorized_keys >/dev/null')                

    def delete_node_handler():
        node = list_nodes()
        print("\n🔴 This will delete records from the accounts. If accounts are needed in future. Replace it with the another node")
        id = custom_input()
        try: 
            selected_node = node[int(id)-1]
        except(IndexError, ValueError):
            custom_input("Invalid ID")
            manage_nodes()
            return
        delete_node(selected_node)

    def clone_node():
        accounts = Accounts.scan()
        nodes = list_nodes()

        selected_node_id = custom_input("Select Node ID to replica")
        selected_target_id = custom_input("Select Target Node ID")
        try:
            selected_node = nodes[int(selected_node_id)-1]
            selected_target = nodes[int(selected_target_id)-1]
        except(IndexError, ValueError):
            custom_input("Invalid ID")
            manage_nodes()
            return
        for account in accounts["Items"]:
            if(account["target"] == selected_node["region"]):
                add_user_in_targeted(account['username'], account['sshkey'], selected_target)

    def user_nav_options(user_input):
        if user_input in exit_commands:
            exit()
        elif user_input == "1":
            clear()
            username = custom_input("Username")
            ssh_key = custom_input("SSH Key")
            add_user_with_replicas(username, ssh_key)
            nodes = list_nodes()
            for node in nodes:
                try:
                    if node["region"] != node_info["region"]:
                        print(node["ipv4"], end="")
                        user_list = get_user_list(node["username"], node["ipv4"])
                        if username not in user_list:
                            os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo useradd -m {username}')
                            os.system(f'ssh {node["username"]}@{node["ipv4"]} sudo -u {username} mkdir -p /home/{username}/.ssh')
                        else:
                            print("\n" + Back.GREEN + "User already exists! Overwriting Keys" + Style.RESET_ALL + " ")
                        os.system(f'ssh {node["username"]}@{node["ipv4"]} \'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
                    else:
                        user_list = get_user_list(no_ssh=True)
                        if username not in user_list:
                            os.system(f'sudo useradd -m {username}')
                            os.system(f'sudo -u {username} mkdir -p /home/{username}/.ssh')
                        else:
                            print("\n" + Back.GREEN + "User already exists! Overwriting Keys" + Style.RESET_ALL + " ")
                        os.system(f'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null')
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
            try:
                selected_node = nodes[int(id)-1]
            except(ValueError, IndexError):
                custom_input("Invalid ID")
                manage_nodes()
                return
            add_user_in_targeted(username, ssh_key, selected_node)
            if selected_node["region"] != node_info["region"]:
                user_list = get_user_list(host_user=selected_node["username"], ip=selected_node["ipv4"])
                if username not in selected_node["username"]:
                    os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo useradd -m {username}')
                    os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} sudo -u {username} mkdir -p /home/{username}/.ssh')
                    os.system(f'ssh {selected_node["username"]}@{selected_node["ipv4"]} \'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null\'')
                else:
                    print("\n" + Back.GREEN + "User already exists! Use modify key option to update a key" + Style.RESET_ALL + " ")
                    manage_users()
            else:
                user_list = get_user_list(no_ssh=True)
                if username not in user_list:
                    os.system(f'sudo useradd -m {username}')
                    os.system(f'sudo -u {username} mkdir -p /home/{username}/.ssh')
                    os.system(f'echo "{ssh_key}" | sudo -u {username} tee /home/{username}/.ssh/authorized_keys >/dev/null')
                else:
                    print("\n" + Back.GREEN + "User already exists! Use modify key option to update a key" + Style.RESET_ALL + " ")
                    manage_users()
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
        if user_input in exit_commands:
            exit()
        elif user_input == "1":
            list_nodes()
            custom_input()
            manage_nodes()
        elif user_input == "2":
            sync_node_handler()
        elif user_input == "3":
            delete_node_handler()
        elif user_input == "4":
            clone_node()
        elif user_input == "5":
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
        print("1. List Nodes")
        print("2. Sync Node")
        print("3. Delete Node")
        print("4. Replica Node Accounts (Not Synchronizable in Nodes)")
        print("5. Go back to Home")

        user_input = custom_input()
        node_nav_options(user_input)

    def nav_options(user_input):
        if user_input in exit_commands:
            exit()
        elif user_input == "1":
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
        print("1. Init Node")
        print("2. Manage Nodes")
        print("3. Manage Users")

        user_input = custom_input()

        nav_options(user_input)

    if __name__ == "__main__":
        welcome_screen()
except KeyboardInterrupt:
    clear()
    print("Stopped Forcefully!")
    exit()