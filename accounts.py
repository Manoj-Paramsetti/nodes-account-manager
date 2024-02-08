import sys
import os

from colorama import Fore, Back, Style

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///keys.sqlite')
Base = declarative_base()

clear = lambda: os.system('clear')

class Accounts(Base):
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    sshkey = Column(String(900))

class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    ipv4 = Column(String, unique=True)

def init():
    clear()
    print("Initialized DB")
    Base.metadata.create_all(engine)

def custom_input(prompt=""):
    return input("\n" + Back.GREEN + prompt + " > " + Style.RESET_ALL + " ")

Session = sessionmaker(bind=engine)
session = Session()

def add_user_record(username, _ssh_key):
    new_key = Accounts(name=username, sshkey=_ssh_key)
    session.add_all([new_key])
    session.commit()

def update_ssh_key(_id):
    try:
        updator = session.query(Accounts).filter_by(id=_id).first()
        if not updator:
            raise

        new_key = custom_input("New Key")
        updator.sshkey = new_key
        session.commit()
    except:
        print("Wrong ID. Try again")
        custom_input()
        modify_user_handler()

def delete_user(id):
    try:
        record_to_delete = session.query(Accounts).filter_by(id=id).first()
        if not record_to_delete:
            raise
        session.delete(record_to_delete)
        session.commit()
    except:
        print("Wrong ID. Try again")
        custom_input()
        delete_user_handler()

def list_users():
    clear()
    all_accounts = session.query(Accounts).all()

    for account in all_accounts:
        print(account.id, account.name, account.sshkey)
    
def list_nodes():
    pass

def list_all_users():
    list_users()
    custom_input()
    manage_user()

def modify_user_handler():
    list_users()

    id = custom_input("Pass the ID to select")    
    update_ssh_key(id)

def delete_user_handler():
    list_users()
    id = custom_input()
    delete_user(id)

def user_nav_options(user_input):
    if user_input == "1":
        username = custom_input("Username")
        ssh_key = custom_input("SSH Key")

        add_user_record(username, ssh_key)
    elif user_input == "2":
        list_all_users()
    elif user_input == "3":
        modify_user_handler()
    elif user_input == "4":
        delete_user_handler()
    elif user_input == "5":
        welcome_screen()
    else:
        custom_input("Wrong Input")
        manage_user()

def manage_user():
    clear()
    print("1. Add User")
    print("2. List User")
    print("3. Modify Key")
    print("4. Delete User")
    print("5. Go back to Home")

    user_input = custom_input()
    user_nav_options(user_input)

def nav_options(user_input):
    if user_input == "1":
        init()
    elif user_input == "2":
        list_nodes()
    elif user_input == "3":
        manage_user()
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
    if len(sys.argv) == 2 and sys.argv[1] == "init":
        init()
        print("Tables are initiated")
        exit()
    welcome_screen()
    session.close()

# sudo chown user:group user/.ssh/authorized_keys
# sudo useradd -m <username>