#!/usr/bin/python
# -*- coding: utf-8 -*-
# Nombre por lo pronto es "Lapis Mens"

import mysql.connector
from flask import Flask, flash, render_template, request, redirect, url_for, session, request, logging
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from sqlhelpers import *
from forms import *
from functools import wraps
import time

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'Crypto'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please log in', 'danger')
            return redirect(url_for('login'))
    return wrap

def log_in_user(username):
    users = Table("users", "name", "email", "username", "password")  # Primero crea el objeto users
    user = users.getone("username", username)                        # Luego obtén el usuario
    session['logged_in'] = True
    session['username'] = username
    session['name'] = user.get('name')
    session['email'] = user.get('email')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    users = Table("users", "name", "email", "username", "password")


    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        name = form.name.data

        if isnewuser: #checa si existe el usuario
            password = sha256_crypt.encrypt(str(form.password.data))
            users.insert(name, email, username, password)
            log_in_user(username)
            return redirect(url_for('dashboard'))
        else:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        candidate = request.form['password']

        users = Table("users", "name", "email", "username", "password")
        user = users.getone("username", username)
        accpass = user.get('password')

        if accpass is None:
            flash('Username not found', 'danger')
            return redirect(url_for('login'))

        else:
            if sha256_crypt.verify(candidate, accpass):
                log_in_user(username)
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password', 'danger')
                return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/transaction', methods=['GET', 'POST'])
@is_logged_in
def transaction():
    form = SendMoneyForm(request.form)
    balance = get_balance(session.get('username'))

    if request.method == 'POST':
        try:
            send_money(session.get('username'), form.username.data, form.amount.data)
            flash('Transaction successful', 'success')
        except Exception as e:
            flash(str(e), 'danger')

        return redirect(url_for('transaction'))
    

    return render_template('transaction.html',balance=balance, form=form, page='transaction')

app.route('/buy', methods=['GET', 'POST'])
@is_logged_in
def buy():
    form = BuyForm(request.form)
    balance = get_balance(session.get('username'))

    if request.method == 'POST':
        try:
            send_money("Bank", session.get('username'), form.amount.data)
            flash('Purchase successful', 'success')
        except Exception as e:
            flash(str(e), 'danger')

        return redirect(url_for('dashboard'))
    
    return render_template('buy.html', balance=balance, form=form)

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@is_logged_in
def dashboard():
    blockchain = get_blockchain().chain
    ct = time.strftime("%Y-%m-%d %H:%M:%S")

    return render_template('dashboard.html', session=session, ct=ct, blockchain=blockchain, page ='dashboard')

@app.route('/')
def index():
    return render_template('index.html')    

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
