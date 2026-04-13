from flask import Flask, request, abort
from datetime import datetime
from random import randbytes, choice
from subprocess import check_output


app = Flask(__name__)
USERS = {'admin': 't0p5ecr3tp@ss'}
AUTHORIZED = {}
LOGFILE = 'log.txt'
ANSWERS = {'It is certain', 'Reply hazy, try again', "Don’t count on it", 'It is decidedly so', 'Ask again later', 'My reply is no', 'Without a doubt',
           'Better not tell you now', 'My sources say no', 'Yes definitely', 'Cannot predict now', 'Outlook not so good', 'You may rely on it',
           'Concentrate and ask again', 'Very doubtful', 'As I see it, yes', 'Most likely', 'Outlook good', 'Yes', 'Signs point to yes'}


def log(data):
    with open(LOGFILE, 'a') as f:
        f.write(f'{datetime.now()} - {data}\n')


@app.route('/authorize')
def authorize():
    if not request.form:
        log('Request had a bad body')
        abort(400)
    if any(p not in request.form for p in {'username', 'password'}):
        log('Request hit /authorize without the right parameters')
        abort(400)
    if request.form['username'] in USERS:
        log('Request hit /authorize a duplicate username')
        abort(400)
    USERS[request.form['username']] = request.form['password']


@app.route('/login')
def login():
    if not request.form:
        log('Request had a bad body')
        abort(400)
    if any(p not in request.form for p in {'username', 'password'}):
        log('Request hit /login without the right parameters')
        abort(400)
    if request.form['username'] not in USERS:
        log('Request hit /login without a valid username')
        abort(404)
    if USERS[request.form['username']] != request.form['password']:
        log('Request failed to log in')
        abort(403)
    token = randbytes(8).hex()
    AUTHORIZED[request.form['username']] = AUTHORIZED.get(request.form['username'], []) + [token]
    return token


@app.route('/logout')
def logout():
    if not request.form:
        log('Request had a bad body')
        abort(400)
    if any(p not in request.form for p in {'username', 'token'}):
        log('Request hit /logout without the right parameters')
        abort(400)
    if request.form['username'] not in AUTHORIZED:
        log('Request hit /logout without a logged in username')
        abort(401)
    if request.form['token'] not in AUTHORIZED[request.form['username']]:
        log('Request hit /logout without a valid token')
        abort(401)
    AUTHORIZED[request.form['username']].remove(request.form['token'])
    if len(AUTHORIZED[request.form['username']]) < 1:
        AUTHORIZED.pop(request.form['username'])


@app.route('/question')
def question():
    if not request.form:
        log('Request had a bad body')
        abort(400)
    if any(p not in request.form for p in {'username', 'token', 'query'}):
        log('Request hit /question without the right parameters')
        abort(400)
    if request.form['username'] not in AUTHORIZED:
        log('Request hit /question without a logged in username')
        abort(401)
    if request.form['token'] not in AUTHORIZED[request.form['username']]:
        log('Request hit /question without a valid token')
        abort(401)
    return choice(ANSWERS)


@app.route('/admin/readlog')
def readlog():
    if not request.form:
        log('Request had a bad body')
        abort(400)
    if any(p not in request.form for p in {'username', 'token', 'filter'}):
        log('Request hit /admin/readlog without the right parameters')
        abort(400)
    if request.form['username'] not in AUTHORIZED:
        log('Request from hit /admin/readlog without a logged in username')
        abort(401)
    if request.form['token'] not in AUTHORIZED[request.form['username']]:
        log('Request hit /admin/readlog without a valid token')
        abort(401)
    if request.form['username'] != 'admin':
        log('Nonadmin user tried to access /admin/readlog')
        abort(403)
    return check_output(f'grep "{request.form["filter"]}" {LOGFILE} | tail -n 100', shell=True)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
