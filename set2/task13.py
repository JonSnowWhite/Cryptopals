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

cookie = 'cool=yes&who=asked&test=2'
print(dict_to_cookie(cookie_to_dict(cookie)))
assert dict_to_cookie(cookie_to_dict(cookie)) == cookie