from flask import Flask, render_template, request, redirect, flash
import requests
import os
import csv
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret')

PROXIES = {
    "http": os.getenv("HTTP_PROXY"),
    "https": os.getenv("HTTPS_PROXY")
}

@app.route('/', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        first_name = request.form['first_name']
        password = request.form['password']
        tenant = request.form['tenant']
        email_verified = 'email_verified' in request.form

        if tenant == "tenant2":
            kc_username = os.getenv("TENANT2_USERNAME")
            kc_password = os.getenv("TENANT2_PASSWORD")
            realm = "tenant2"
            CSV_FOLDER = "tenant2"
        elif tenant == "tenant3":
            kc_username = os.getenv("TENANT3_USERNAME")
            kc_password = os.getenv("TENANT3_PASSWORD")
            realm = "tenant3"
            CSV_FOLDER = "tenant3"
        elif tenant == "nokiahwstg":
            kc_username = os.getenv("STG_USERNAME")
            kc_password = os.getenv("STG_PASSWORD")
            realm = "nokiahwstg"
            CSV_FOLDER = "demouserl1"
        else:
            flash("Invalid tenant selected", "error")
            return redirect('/')

        os.makedirs(CSV_FOLDER, exist_ok=True)

        result = create_keycloak_user(username, email, first_name, password, email_verified, kc_username, kc_password, realm, CSV_FOLDER)
        if isinstance(result, dict) and 'error' in result:
            flash(f"❌ {result['error']}", 'error')
            return redirect('/')

        flash(f"✅ User '{username}' created successfully in realm '{realm}'", 'success')
        return redirect('/')

    return render_template('form.html')

def get_access_token(username, password, realm):
    token_url = f"https://auth.stg.homewifi.nokia.com/sso/realms/{realm}/protocol/openid-connect/token"
    payload = {
        'grant_type': 'password',
        'client_id': 'admin-cli',
        'username': username,
        'password': password
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(token_url, data=payload, headers=headers, proxies=PROXIES, timeout=10)
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        print("❌ Failed to retrieve token:", response.status_code, response.text)
        return None

def create_keycloak_user(username, email, first_name, password, email_verified, kc_username, kc_password, realm, CSV_FOLDER):
    token = get_access_token(kc_username, kc_password, realm)
    if not token:
        return {"error": "Failed to get access token."}

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    base_url = f"https://auth.stg.homewifi.nokia.com/sso/admin/realms/{realm}"
    user_url = f"{base_url}/users"
    payload = {
        'username': username,
        'email': email,
        'firstName': first_name,
        'enabled': True,
        'emailVerified': email_verified,
        'attributes': {'locale': 'en'}
    }

    create_resp = requests.post(user_url, json=payload, headers=headers, proxies=PROXIES, timeout=10)
    if create_resp.status_code == 201:
        lookup_resp = requests.get(user_url + f"?username={username}", headers=headers, proxies=PROXIES, timeout=10)
        if lookup_resp.status_code == 200 and lookup_resp.json():
            user_id = lookup_resp.json()[0]['id']

            pwd_url = f"{user_url}/{user_id}/reset-password"
            pwd_payload = {
                'type': 'password',
                'value': password,
                'temporary': False
            }
            pwd_resp = requests.put(pwd_url, json=pwd_payload, headers=headers, proxies=PROXIES, timeout=10)
            if pwd_resp.status_code != 204:
                return {"error": f"Password set failed. Code: {pwd_resp.status_code}"}

            # Assign Groups
            group_list = ['/everyone']
            try:
                with open(os.path.join(CSV_FOLDER, 'groups.csv'), 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row:
                            group_list.append(f"/{row[0].strip()}")
            except:
                print("No groups.csv found")

            group_resp = requests.get(f"{base_url}/groups", headers=headers, proxies=PROXIES, timeout=10)
            if group_resp.status_code == 200:
                all_groups = group_resp.json()
                for group_path in group_list:
                    group_obj = next((g for g in all_groups if g["path"] == group_path), None)
                    if group_obj:
                        assign_url = f"{user_url}/{user_id}/groups/{group_obj['id']}"
                        requests.put(assign_url, headers=headers, proxies=PROXIES, timeout=10)

            # Assign Realm Roles
            try:
                with open(os.path.join(CSV_FOLDER, 'realm_roles.csv'), 'r') as f:
                    roles = [row[0].strip() for row in csv.reader(f) if row]
                if roles:
                    role_resp = requests.get(f"{base_url}/roles", headers=headers, proxies=PROXIES, timeout=10)
                    if role_resp.status_code == 200:
                        available_roles = role_resp.json()
                        matched_roles = [r for r in available_roles if r['name'] in roles]
                        assign_url = f"{user_url}/{user_id}/role-mappings/realm"
                        requests.post(assign_url, json=[], headers=headers, proxies=PROXIES, timeout=10)
                        if matched_roles:
                            assign_resp = requests.post(assign_url, json=matched_roles, headers=headers, proxies=PROXIES, timeout=10)
                            if assign_resp.status_code != 204:
                                return {"error": f"Realm Role assign failed. Code: {assign_resp.status_code}, {assign_resp.text}"}
            except:
                print("No realm_roles.csv found")

            return user_id
        else:
            return {"error": "User created but lookup failed."}
    elif create_resp.status_code == 409:
        return {"error": "User with same email or username already exists."}
    else:
        return {"error": f"Failed to create user. Code: {create_resp.status_code}, {create_resp.text}"}

if __name__ == '__main__':
    app.run(debug=True)