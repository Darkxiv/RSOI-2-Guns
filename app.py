# coding: utf-8

from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import gen_salt
from flask_oauthlib.provider import OAuth2Provider
import json, math

app = Flask(__name__, template_folder='templates')
app.debug = True
app.secret_key = 'secret'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)
#oauth = OAuth2Provider(app)

SALT_LENGTH = 3

class WeaponType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)

class Weapon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True)
    type = db.Column(db.Integer, db.ForeignKey(WeaponType.id))
    weapontype = db.relationship('WeaponType')
    cost = db.Column(db.Integer)
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    pas = db.Column(db.String(40), unique=False)
    mail = db.Column(db.String(60), unique=True)
    telnum = db.Column(db.String(20), unique=True)

class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]



class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self



class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

def get_user_by_id(user_id):
    user = User.query.filter_by(id=user_id).first()
    return user

@app.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        telnum = request.form.get('telnum')
        mail = request.form.get('mail')
        pas = request.form.get('pas')
        user = User.query.filter_by(username=username).first()
        testn = User.query.filter_by(telnum=telnum).first()
        testm = User.query.filter_by(mail=mail).first()
        if not (user or testn or testm):
            user = User(username=username, pas=pas, telnum=telnum, mail=mail)
            db.session.add(user)
            db.session.commit()
            session['id'] = user.id
        if user and (pas == user.pas):
            session['id'] = user.id
        return redirect('/')
    user = current_user()
    return render_template('home.html', user=user)


@app.route('/exit')
def uexit():
	session.clear()
	return redirect('/')

@app.route('/client')
def client():
    user = current_user()
    if not user:
        return redirect('/')
    item = Client(
        client_id=gen_salt(SALT_LENGTH),
        client_secret=gen_salt(SALT_LENGTH),
        _redirect_uris=' '.join([
            'http://localhost:8000/login',
            'http://127.0.0.1:8000/login',
            'http://127.0.1:8000/login',
            'http://127.1:8000/login',
            'http://localhost:8000/authorized',
            'http://127.0.0.1:8000/authorized',
            'http://127.0.1:8000/authorized',
            'http://127.1:8000/authorized',
            ]),
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )


#@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


#@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


#@oauth.grantsetter
def save_grant(client_id, code, redirect_uri):
    print ("save_grant\n")
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code,
        redirect_uri=redirect_uri,
        user=current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


#@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    print ("load token\n")
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


#@oauth.tokensetter
def save_token(token, client_id, user_id):
    print ("save token\n")
    toks = Token.query.filter_by(
        client_id=client_id,
        user_id=user_id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires = datetime.utcnow() + timedelta(seconds=1000)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        expires=expires,
        client_id=client_id,
        user_id=user_id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok

def delete_token(token):
    Token.query.filter_by(access_token=token).delete()
    db.session.commit()
    return None

#logic: 
#1) authorize app -> get client_id, redir, status; return auth_code, status (if user access)
# compare client_id, redir
#2) send token -> get auth_code, client_id, client_secret, redir, grant_type; return token
#compare client_id, client_secret, auth_code; return token if everything is normal
#3) work (expire???)

def check_oauth(request):
    access_token = request.headers.get('access_token', '')
    refresh_token = request.headers.get('refresh_token', '')
    token = load_token(access_token, refresh_token)
    if token:
        if datetime.utcnow() < token.expires:
            return token
    return None

def gen_token():
    return {'access_token': gen_salt(SALT_LENGTH), 'refresh_token': gen_salt(SALT_LENGTH), 'token_type': 'bearer'}

@app.route('/oauth/token', methods=['GET', 'POST'])
#@oauth.token_handler
def access_token():
    client_id = request.args.get('client_id', '')
    print("client_id: " + client_id + "\n")
    client = load_client(client_id)           
    if client:
        #check expire
        client_secret = request.headers.get('client_secret')
        #check secret
        redirect_uri = request.args.get('redirect_uri', '')
        #check uri
        
        code = request.args.get('code', '')
        grant_type = request.args.get('grant_type', 'authorization_code')
        print("grant_type: " + grant_type)
        if grant_type == 'authorization_code':
            grant = load_grant(client_id, code)
            if grant:
                #clear dbs            
                #create token
                token = gen_token()
                save_token(token, client_id, grant.user_id)
                print ("return access\n")
                return jsonify(access_token = token['access_token'], refresh_token = token['refresh_token'])
        else:
            refresh_token = request.headers.get('refresh_token')
            if refresh_token:
                token = load_token(None, refresh_token)
                if token:
                    delete_token(token.access_token)
                    new_token = gen_token()
                    save_token(new_token, client_id, token.user_id)
                    return jsonify(access_token = new_token['access_token'], refresh_token = new_token['refresh_token'])
    print ('FAIL - /oauth/token\n')
    return 'FAIL - /oauth/token'

@app.route('/oauth/authorize', methods=['GET', 'POST'])
#@oauth.authorize_handler
def authorize():
    state = request.args.get('state')
    client_id = request.args.get('client_id')
    client = Client.query.filter_by(client_id=client_id).first()
    redirect_uri = request.args.get('redirect_uri', '')
    if client:
        user = current_user()
        if not user:
            if request.method == 'POST':
                username = request.form.get('username')
                pas = request.form.get('pas')
                user = User.query.filter_by(username=username).first()
                if user and (pas == user.pas):
                    session['id'] = user.id
                    return render_template('authorize.html', client_id=client_id, state=state, username=username, redirect_uri=redirect_uri) 
            return render_template('login.html', client_id=client_id, state=state, redirect_uri=redirect_uri)

        if request.method == 'GET':
            return render_template('authorize.html', client_id=client_id, state=state, username=user.username, redirect_uri=redirect_uri)

        confirm = request.form.get('confirm', 'no')
        if confirm == 'yes':
            #check redirect_uri
            state = request.args.get('state', '')
            code = gen_salt(SALT_LENGTH)
            save_grant(client_id, code, redirect_uri)
            print ("code: " + code)
            return redirect(redirect_uri + "?code=" + code + "&state=" + state)

    print ('FAIL - /oauth/authorize\n')
    return 'FAIL - /oauth/authorize'
'''
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        print ("return template\n")
        return render_template('authorize.html', **kwargs)

    print ("return confrim\n")
    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'
'''

@app.route('/api/me', methods=['GET', 'POST'])
#@oauth.require_oauth()
def me():
    token = check_oauth(request) 
    if not token:
        return 'Fail with authorization'
    user = get_user_by_id(token.user_id)
    return jsonify(username=user.username, telephone_number=user.telnum, id=user.id)

@app.route('/api/status')
def status():
    count = db.session.query(Weapon).count()
    answer = {'Guns count': count}
    return jsonify(answer)

@app.route('/api/guns', methods=['GET', 'POST'])
#@oauth.require_oauth()
def show_guns():
    if not check_oauth(request):
        return 'Fail with authorization'
    pp = int(request.args.get('pp', -1))
    p = int(request.args.get('p', 1))
    
    guns = Weapon.query.all()
    count = db.session.query(Weapon).count()
    
    if pp <= 0:
        pp = count
        max_page = 1
    else:
        max_page = int(math.ceil(count * 1.0 / pp))
        
    if (p < 1) or (p > max_page):
        p = max_page
    
    array = []
    cc = 0
    #set paging
    for g in guns:
        wtp = WeaponType.query.filter_by(id=g.type).first()
        key = {'id': g.id, 'name': g.name, 'type': wtp.name}
        cc += 1
        if (cc > (p-1)*pp):
            array.append(key)
            if cc == p*pp:
                break
    output = {'elements': array, 'page': p, 'max_page': max_page, 'count': count}
    return json.dumps(output)

@app.route('/api/guns/<int:gun_id>', methods=['GET', 'POST'])
#@oauth.require_oauth()
def show_gun(gun_id):
    if not check_oauth(request):
        return 'Fail with authorization'
    g = Weapon.query.filter_by(id=gun_id).first()
    if g:
        wtp = WeaponType.query.filter_by(id=g.type).first()
        return jsonify(id=g.id, name=g.name, type=wtp.name, cost=g.cost)
    return 'not found :P'


@app.route('/api/types', methods=['GET', 'POST'])
##@oauth.require_oauth()
def show_guns_by_type():
    if not check_oauth(request):
        return 'Fail with authorization'
    pp = int(request.args.get('pp', -1))
    p = int(request.args.get('p', 1))
    
    count = db.session.query(WeaponType).count()
    types = WeaponType.query.all()
    
    if pp <= 0:
        pp = count
        max_page = 1
    else:
        max_page = int(math.ceil(count * 1.0 / pp))
        
    if (p < 1) or (p > max_page):
        p = max_page
    
    array = []
    cc = 0
    
    for t in types:
        key = {'id': t.id, 'name': t.name}
        cc += 1
        if (cc > (p-1)*pp):
            array.append(key)
            if cc == p*pp:
                break
    output = {'elements': array, 'page': p, 'max_page': max_page, 'count': count}
    return json.dumps(output)

@app.route('/api/types/<int:type_id>', methods=['GET', 'POST'])
##@oauth.require_oauth()
def show_type(type_id):
    if not check_oauth(request):
        return 'Fail with authorization'
    wtp = WeaponType.query.filter_by(id=type_id).first()
    if wtp:
        count = Weapon.query.filter_by(type=wtp.id).count()
        return jsonify(id=wtp.id, name = wtp.name, count = count)
    return 'not found :P'

@app.route('/load_some_data', methods=['GET', 'POST'])
def load_some_data():
    try:
        t1 = WeaponType(name='pistol')
        t2 = WeaponType(name='rifle')
        db.session.add(t1)
        db.session.commit()
        db.session.add(t2)
        db.session.commit()
        pid = WeaponType.query.filter_by(name='pistol').first()
        rid = WeaponType.query.filter_by(name='rifle').first()

        for i in range(1, 6):
            n = "Colt " + str(i*2) + "'"
            w = Weapon(name=n, type=pid.id, cost = i * 1000)
            db.session.add(w)
            db.session.commit()
        
        for i in range(2, 8):
            n = "A Gun " + str(i) + "'"
            w = Weapon(name=n, type=pid.id, cost = i * 100)
            db.session.add(w)
            db.session.commit()

        for i in range(4, 10):
            n = "Desert Eagle " + str(i*5) + "'"
            w = Weapon(name=n, type=pid.id, cost = i * 1500)
            db.session.add(w)
            db.session.commit()
        
        for i in range(7, 12):
            n = "Smoked barrel " + str(i*3) + "'"
            w = Weapon(name=n, type=rid.id, cost = i * 800)
            db.session.add(w)
            db.session.commit()
            
        for i in range(9, 12):
            n = "Snipers rifle " + str(i*4) + "'"
            w = Weapon(name=n, type=rid.id, cost = i * 2000)
            db.session.add(w)
            db.session.commit()
    except:
        return 'Already loaded'
    return 'Success'


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
