import ssl
from ldap3 import Tls, NTLM, Connection, Server, SUBTREE, MODIFY_REPLACE

from utils import decode_str, get_config_value

config_path = 'config.ini'
host = get_config_value(config_path, 'ldap', 'host')
port = get_config_value(config_path, 'ldap', 'port')
domain = get_config_value(config_path, 'ldap', 'domain')
base_dn = get_config_value(config_path, 'ldap', 'base_dn')
user = get_config_value(config_path, 'ldap', 'user')
password = decode_str(get_config_value(config_path, 'ldap', 'password'))

class LDAP_OP(object):
    def __init__(self):
        self.user = user
        self.password = password
        self.host = host
        self.port = int(port)
        self.domain = domain
        self.base_dn = base_dn

    def conn_res(self):
        tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        s = Server(host=self.host, port=self.port, use_ssl=True, tls=tls_configuration)
        conn = Connection(s, self.domain + "\\" + self.user, self.password, authentication=NTLM)
        try:
            conn.start_tls()
        except Exception as e:
            #return e
            return False
        try:
            conn.bind()
            if not conn.bind():
                conn.unbind()
                #return "Invalid credentials"
                return False
        except Exception as e:
            #return e
            return False
        return conn

    def authenticate(self, username, password):
        tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        # define the server and the connection
        s = Server(self.domain, port=self.port, use_ssl=True, tls=tls_configuration)
        conn = Connection(s, domain + "\\" + username, password, authentication=NTLM)
        conn.start_tls()
        conn.bind()
        try:
            if not conn.bind():
                print("Not Connected")
                conn.unbind()
                return False
            else:
                print("Connected")
                conn.unbind()
                return True
        finally:
            pass

    def search_user(self, conn, username):
        if conn == False:
            return "bind failed"
        SEARCHFILTER = '(&(|' \
                       '(userPrincipalName=' + username + ')' \
                                                          '(samaccountname=' + username + ')' \
                                                                                          '(mail=' + username + '))' \
                                                                                                                '(objectClass=person))'
        conn.search(search_base=base_dn, search_filter=SEARCHFILTER,
                    attributes=['*'], search_scope=SUBTREE, paged_size=5)
                    #search_scope=SUBTREE, attributes=['cn', 'mail'], paged_size=5)

        for entry in conn.response:
            return entry.get("attributes")
        return "user not exist"

    def reset_passwd(self, conn, username, new_passwd):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return search_user_res
        user_dn = search_user_res["distinguishedName"]
        try:
            enc_pwd = '"{}"'.format(new_passwd).encode('utf-16-le')
            changes = {'unicodePwd': [(MODIFY_REPLACE, [enc_pwd])]}
            x = conn.modify(user_dn, changes=changes)
            print("res: " + str(x))
            # Slack Notification for the user
            # a new password is set, hashed with sha256 and a random salt
            return x
        except Exception as e:
            return False

