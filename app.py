# mongo connectors
import pymongo
from pymongo import MongoClient

import bcrypt
import nacl, nacl.secret, nacl.utils
from nacl.public import PrivateKey, SealedBox
from binascii import hexlify

# database connection
mongoClient = MongoClient('mongodb://localhost:27017/')
db = None
users = None
reports = None

# salting
salt = bcrypt.gensalt(rounds = 12)

# user logged in
loggedIn = False

# symetric encryption
box = None
userKey = None # this will be assigned after the user logs in

def initDatabase():
    # using global vars
    global db
    global users
    global reports
    # Get the database and users collection
    db = mongoClient.crypto_db
    users = db.users
    reports = db.reports
    if db:
        print('Connected to db')
        return True

# setting up db connection
initDatabase()

def insertUser(user):
    global salt
    global users
    global box
    print(user['password'])
    print(bcrypt.hashpw(user['password'].encode('utf-8'), salt))
    # hashing the password
    hashedPw = bcrypt.hashpw(user['password'].encode('utf-8'), salt)

    # saving hashed password back into user object
    user['password'] = hashedPw

    # generate a random 32 byte key
    userSecretKey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # assigning secret key to user object  
    user['key'] = userSecretKey
    # inserting user object in database
    users.insert_one(user)
    print("User " + user['username'] + " has just been created \n")

# adds a report to database
def addReport(report):
    global reports
    global box
    text = report['report']
    key = report['key']
    # store key in the safe
    box = nacl.secret.SecretBox(key)
    # generate nonce for extra randomness
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    # encrypt the message
    encrypted = box.encrypt(text, nonce)

    if reports.insert_one({'report': encrypted}):
        return True
    else:
        return False

# read reports
def readReports():
    # key to decrypt the messages
    global userKey
    global reports

    for report in reports.find():
        try:
            # store key in the safe
            box = nacl.secret.SecretBox(userKey)
            decryptedReport = box.decrypt(report['report'])

            print(decryptedReport)
        except:
            print()

# login user
def login(userToLogin):
    global users
    global salt
    global userKey
    # finding object with the same username
    user = users.find_one({'username': userToLogin['username']})
    # if user exists
    if user:
        if bcrypt.hashpw(userToLogin['password'].encode('utf-8'), user['password']) == user['password']:
            userKey = user['key']
            # print('This is the user key')
            # print(userKey)
            return True
        else:
            # print('no match')
            return False
    else:
        print('User cannot be found')


while True:
    print('Press 1 for creating a user')
    print('Press 2 for logging in')

    choice = input('press a number: ')
    # getting user input
    # add a new user to db
    username = input('Enter username: ')
    password = input('Enter password: ')

    user = {
    'username': username,
    'password': password,
    'key': None
    }
    if choice == '1':
        password2 = input('Repeat the password: ')
        if password2 == user['password']:
            # create user
            insertUser(user)
        else:
            print('Passwords do not match!')
    else:
        # login user
        if login(user):
            loggedIn = True
            print('You are logged in as ' + user['username'])
            # setting
            break


while True:
    print('Press 1 for adding a new report')
    print('Press 2 for reading your reports')
    print('Press 3 to exit')

    choice = input('press a number: ')

    if loggedIn and choice == '1':
        # add a report
        report = input('Add a report: ').encode('utf-8')
        report = {
            'report': report,
            'key': userKey
        }
        if addReport(report):
            print('Report added!')
        else:
            print('Report not added')
    if loggedIn and choice == '2':
        readReports()
    if loggedIn and choice == '3':
        break