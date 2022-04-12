def cookie_to_dict(cookie: str):
    ret = {}
    pairs = cookie.split('&')
    for pair in pairs:
        key, value = pair.split('=')
        ret[key] = value
    return ret

def dict_to_cookie(dct: dict):
    cookie = ''
    for key, value in dct.items():
        cookie = f'{cookie}{key}={value}&'
    return cookie[:-1]

def profile_for(email: str):
    dct = {}
    email = email.replace("&","").replace("=","")
    dct['email'] = email
    dct['uid'] = 10
    dct['role'] = 'user'

cookie = 'cool=yes&who=asked&test=2'
assert dict_to_cookie(cookie_to_dict(cookie)) == cookie

