import urllib, urllib2, base64, json
from flask import Flask, url_for, session, request, jsonify, redirect
from flask_oauthlib.client import OAuth


CLIENT_ID = 'cIk'
CLIENT_SECRET = 'aMZY'
myState = 'AdventureTime'

app = Flask(__name__)
app.debug = True
app.secret_key = 'secret'
#oauth = OAuth(app)
'''
remote = oauth.remote_app(
    'remote',
    consumer_key=CLIENT_ID,
    consumer_secret=CLIENT_SECRET,
    request_token_params={
        'scope': 'all',
        'state': 'adventureTime'
    },
    base_url='http://127.0.0.1:5000/api/',
    request_token_url=None,
    access_token_url='http://127.0.0.1:5000/oauth/token',
    authorize_url='http://127.0.0.1:5000/oauth/authorize',
)
'''

@app.route('/exit')
def exit():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    args = {
        'code': code,
        'client_id': CLIENT_ID,
        'state': myState,
    }

    if state != myState:
        #return redirect("http://127.0.0.1:5000/oauth/authorize?client_id=" + args["client_id"] + "&response_type=code&redirect_uri=http://localhost:8000/login&state=" + args["state"])
        return redirect("http://127.0.0.1:5000/oauth/authorize?client_id=" + args["client_id"] + "&response_type=code&state=" + args["state"])
    else:
        session['code'] = code
    
    try:
        url = 'http://127.0.0.1:5000/oauth/token?code=' + args['code'] + '&client_id=' + args['client_id'] + '&redirect_uri=http://localhost:8000/login'
        '''
        values = {'code' : code,
                'grant_type' : 'authorization_code',
                'redirect_uri' : 'http://localhost:8000/login',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET } # need to greed
        '''
        values = { 'client_secret': CLIENT_SECRET }
        data = urllib.urlencode(values)
        req = urllib2.Request(url, data)
        resp = urllib2.urlopen(req)
        dresp = json.loads(resp.read())
        session['access_token'] = dresp['access_token']
        session['refresh_token'] = dresp['refresh_token']
        return "OK " + session['access_token'] + "  " + session['refresh_token']
    except urllib2.HTTPError, error:
        contents = error.read()
        return "FAIL: "  + contents
'''
    if 'remote_oauth' in session:
        print session['remote_oauth']
        resp = remote.get('me')
        print resp.data
        return jsonify(resp.data)
    next_url = request.args.get('next') or request.referrer or None
    return remote.authorize(
        callback=url_for('authorized', next=next_url, _external=True)
    )
'''

@app.route('/authorized')
def authorized():
    #curl -sS 'http://127.0.0.1:5000/oauth/token?code=3HS8kIIpv0jSxfDmlbvQN5ZPZ7CKpY&client_id=fJB&client_secret=t2pI&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&grant_type=authorization_code'
    #code = request.args.get('code', '')
    resp = remote.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    print resp
    session['remote_oauth'] = (resp['access_token'], '')
    return jsonify(oauth_token=resp['access_token'])
    #return code
    
#@remote.tokengetter
def get_oauth_token():
    return session.get('remote_oauth')


if __name__ == '__main__':
    import os
    os.environ['DEBUG'] = 'true'
    #os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    app.run(host='localhost', port=8000)
