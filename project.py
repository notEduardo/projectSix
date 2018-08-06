from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from flask import session as login_session
import random
import string
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker, scoped_session
from my_database_setup import Base, Category, Item

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Load the client_id from the json file given to us by google
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']


# I kept having issues with threading so i created a function
# that is called at the beginning of every function that
# will create a connection to the database.
def createConnection():
    engine = create_engine('sqlite:///category.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    return session


# Google connect functions
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    # This token is the same one that we send in the post request
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    # We only obtian this code if the state token is validated
    code = request.data

    # Now we either upgrade our authorization code or send
    # back an error saying we couldn't do so
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid by sending it to
    # the google servers.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    print(url)
    result = json.loads(requests.get(url).text)

    # If there was an error in the access token info, return
    # and print out the error that was returned to us
    if result.get('error') is not None:
        print("-----------------------------------")
        print(result.get('error'))
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # We make sure that the current user (the on trying to login)
    # is not already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        jsonVar = json.dumps('Current user is already connected.')
        response = make_response(jsonVar, 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    print(login_session['access_token'])
    print("---------------")
    print(data)
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash('Successfully Logged In')
    print ("done!")
    return output


# Google disconnect functions
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        jsonVar = json.dumps('Current user is not connected.')
        response = make_response(jsonVar, 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute revoke request
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    print (result)

    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully Logged Out')
        return redirect(url_for('showCategories'))
    else:
        response = make_response(json.dumps('Failed to revoke token.', 400))
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('showCategories'))


# JSON functions
# JSON function to return the category page
@app.route('/category/JSON')
def categoriesJSON():
    session = createConnection()
    categories = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in categories])


# JSON function to return the items page
@app.route('/category/<int:category_id>/items/JSON')
def categoryItemsJSON(category_id):
    session = createConnection()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON function to return i single item page
@app.route('/category/<int:category_id>/items/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    session = createConnection()
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    session = createConnection()
    categories = session.query(Category).order_by(asc(Category.name))
    log = True
    if 'username' not in login_session:
        log = False
    return render_template('main.html',
                           categories=categories, loggedIn=log)


# Show webpage for editing a category
@app.route('/category/<int:category_id>/edit', methods={'GET', 'POST'})
def editCategory(category_id):
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    print(login_session['username'])
    # First obtain a connection to the database
    session = createConnection()
    # Second we obtain a copy of the category we want to edit
    editedCat = session.query(Category).filter_by(id=category_id).one()
    # If the function as accessed as a POST method we edit the
    # variable using the request method from the .html page
    if request.method == 'POST':
        if request.form['name']:
            editedCat.name = request.form['name']
        session.add(editedCat)
        flash('Restaurant Successfully Edited %s' % editedCat.name)
        session.commit()
        return redirect(url_for('showCategories'))
    # If the funtion is accessed as a GET method then we simply
    # render the designated template for this URL
    else:
        return render_template('editCategory.html', category=editedCat)


# Show webpage for deleting a category
@app.route('/category/<int:category_id>/delete', methods={'GET', 'POST'})
def deleteCategory(category_id):
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    # First obtain a connection to the database
    session = createConnection()
    # Second we obtain a copy of the category we want to delete
    deletedCat = session.query(Category).filter_by(id=category_id).one()
    # If the function as accessed as a POST method we delete
    # using the category variable we just obtained
    if request.method == 'POST':
        session.delete(deletedCat)
        flash('Successfully Deleted %s' % deletedCat.name)
        session.commit()
        return redirect(url_for('showCategories'))
    # If the funtion is accessed as a GET method then we simply
    # render the designated template for this URL
    else:
        return render_template('deleteCategory.html', category=deletedCat)


# Show webpage for creating a new category
@app.route('/category/new', methods={'GET', 'POST'})
def newCategory():
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    # First obtain a connection to the database
    session = createConnection()
    # If the function as accessed as a POST method we create
    # a new category variable using the class constructor
    if request.method == 'POST':
        newCat = Category(name=request.form['name'])
        session.add(newCat)
        flash('Successfully added %s' % newCat.name)
        session.commit()
        return redirect(url_for('showCategories'))
    # If the funtion is accessed as a GET method then we simply
    # render the designated template for this URL
    else:
        return render_template('newCategory.html')


# Show webpage for a single item
@app.route('/category/<int:category_id>/items/<int:item_id>')
def oneItem(category_id, item_id):
    session = createConnection()
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('oneItem.html', item=item, category=category)


# Show webpage for items of a category
@app.route('/category/<int:category_id>/items')
def showItems(category_id):
    session = createConnection()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return render_template('items.html', items=items, category=category)


# Show webpage for editing an item
@app.route('/category/<int:category_id>/items/<int:item_id>/edit',
           methods=['POST', 'GET'])
def editItem(category_id, item_id):
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    # First obtain a connection to the database
    session = createConnection()
    # Second we obtain a copy of the item we want to edit
    editedItem = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        flash('Restaurant Successfully Edited %s' % editedItem.name)
        session.commit()
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('editItem.html',
                               item=editedItem,
                               category_id=category_id)


# Show webpage for deleting an item
@app.route('/category/<int:category_id>/items/<int:item_id>/delete',
           methods=['POST', 'GET'])
def deleteItem(category_id, item_id):
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    # First obtain a connection to the database
    session = createConnection()
    # Second we obtain a copy of the item we want to delete
    deletedItem = session.query(Item).filter_by(id=item_id).one()
    # If the function as accessed as a POST method we delete
    # using the item variable we just obtained
    if request.method == 'POST':
        session.delete(deletedItem)
        flash('Restaurant Successfully Deleted %s' % deletedItem.name)
        session.commit()
        return redirect(url_for('showItems', category_id=category_id))
    # If the funtion is accessed as a GET method then we simply
    # render the designated template for this URL
    else:
        return render_template('deleteItem.html',
                               item=deletedItem,
                               category_id=category_id)


# Show webpage for creating a new item
@app.route('/category/<int:category_id>/items/new',
           methods=['POST', 'GET'])
def newItem(category_id):
    # check if the user is logged in
    if 'username' not in login_session:
        return redirect('/login')
    # First obtain a connection to the database
    session = createConnection()
    # Second we obtain a connection the category we're adding to
    category = session.query(Category).filter_by(id=category_id).one()
    # If the function as accessed as a POST method we create a
    # new item variable using the item class constructor
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category_id)
        session.add(newItem)
        flash('Successfully added %s' % newItem.name)
        session.commit()
        return redirect(url_for('showItems', category_id=category_id))
    # If the funtion is accessed as a GET method then we simply
    # render the designated template for this URL
    else:
        return render_template('newItem.html', category_id=category_id)


# Show webpage for logging in
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

if __name__ == '__main__':
    app.secret_key = 'my_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
