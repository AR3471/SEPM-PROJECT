import requests

r = requests.post('http://127.0.0.1:5000/api/auth/register', json={
    'username': 'tester',
    'email': 't@example.com',
    'password': 'test123',
})
print(r.status_code)
print(r.text)
