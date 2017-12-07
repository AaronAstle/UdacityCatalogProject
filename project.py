#!/usr/bin/python
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask import session as login_session

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials

from functools import wraps

import httplib2
import json
import random
import requests
import string


app = Flask(__name__)

# Client Secrets
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Bikes N Stuff"


# DB Connection and Session
engine = create_engine('sqlite:///bikes.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind = engine)
session = DBSession()


# Authentication
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

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

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
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
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], image_url=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None# Disconnect based on provider


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showLanding'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showLanding'))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' in login_session:
            return f(*args, **kwargs)
        flash("Please log in to add, edit and delete content")
        return redirect('/login')
    return decorated_function


# App Routing
@app.route('/')
@app.route('/catalog')
def showLanding():
    categories = session.query(Category).order_by(asc(Category.name))
    latestItems = session.query(Item).order_by(Item.id.desc())
    return render_template(
        'index.html',
        categories=categories,
        latestItems=latestItems)


@app.route('/catalog/<int:category_id>/items')
def showItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return render_template('items.html', items=items, category=category)


# Show an items's details
@app.route('/catalog/<int:category_id>/<int:item_id>')
def itemDetails(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('item.html', item=item, category=category)



@app.route('/catalog/items/new', methods=['GET', 'POST'])
@login_required
def newItem():
    categories = session.query(Category).order_by(asc(Category.name))
    user_id = login_session['user_id']
    if request.method == 'POST':
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        newItem = Item(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            category_id=category.id,
            created=datetime.datetime.now(),
            user_id=user_id)
        session.add(newItem)
        session.commit()
        flash('New Item -  %s  Successfully Created' % (newItem.name))
        return redirect(url_for('showLanding'))
    else:
        return render_template('newitem.html', categories=categories)

# Edit an item


@app.route('/catalog/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def editItem(item_id):
    categories = session.query(Category).order_by(asc(Category.name))
    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit other users' items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            category = session.query(Category).filter_by(
                name=request.form['category']).one()
            item.name = request.form['name']
            item.description = request.form['description']
            item.price = request.form['price']

            item.category_id = category.id
            flash('%s Successfully Edited' % item.name)
            return redirect(url_for('showItems', category_id=item.category.id))
    else:
        return render_template(
            'edititem.html',
            categories=categories,
            item=item)


# Delete an item
@app.route('/catalog/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteItem(item_id):
    item = session.query(Item).filter_by(id=item_id).one()
    if item.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete other users' items.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(item)
        flash('%s Successfully Deleted' % item.name)
        session.commit()
        return redirect(url_for('showItems', category_id=item.category.id))
    else:
        return render_template('deleteitem.html', item=item)

# Add a new category


@app.route('/catalog/new', methods=['GET', 'POST'])
@login_required
def newCategory():
    user_id = login_session['user_id']
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'], user_id=user_id)
        session.add(newCategory)
        session.commit()
        flash('New Category %s Successfully Created' % (newCategory.name))
        return redirect(url_for('showLanding'))
    else:
        return render_template('newcategory.html')


# Edit a category
@app.route('/catalog/category/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit other users' categories.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            flash('%s Successfully Edited' % category.name)
            return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('editCategory.html', category=category)


# Delete a category and all of the items associated with it
@app.route(
    '/catalog/category/<int:category_id>/delete',
    methods=[
        'GET',
        'POST'])
@login_required
def deleteCategory(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    if category.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete other users' categories.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        for item in items:
            session.delete(item)
        session.delete(category)
        flash(
            '%s Category and All Items Associated with this Category Successfully Deleted' %
            category.name)
        session.commit()
        return redirect(url_for('showLanding'))
    else:
        return render_template('deleteCategory.html', category=category)


# Boilerplate App Run
if __name__ == '__main__':
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
