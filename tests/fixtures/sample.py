import os
import pickle

def login(username, password):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    result = os.system(f"echo {username}")
    exec(f"print('Hello {username}')")
    data = pickle.loads(password)
    return eval(username + " + 'test'")
