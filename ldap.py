import ssl
from ldap3 import Tls, NTLM, Connection, Server, SUBTREE, MODIFY_REPLACE
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
from ldap3.extend.microsoft.removeMembersFromGroups import ad_remove_members_from_groups
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
                #conn.unbind()
                return False
            else:
                print("Connected")
                #conn.unbind()
                return True
        finally:
            conn.unbind()

    def search_user(self, conn, username):
        if conn == False:
            return "bind failed"
        SEARCHFILTER = '(&(|' \
                       '(userPrincipalName=' + username + ')' \
                                                          '(samaccountname=' + username + ')' \
                                                                                          '(mail=' + username + '))' \
                                                                                                                '(objectClass=person))'
        conn.search(search_base=base_dn,
                    search_filter=SEARCHFILTER,
                    attributes=['*'],
                    search_scope=SUBTREE,
                    paged_size=5)
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

    def modify_user(self, conn, username, attribute, new_value):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return search_user_res
        user_dn = search_user_res["distinguishedName"]
        modify_res = conn.modify(user_dn, {attribute: [(MODIFY_REPLACE, [new_value])]})
        return modify_res

    def disable_user(self, conn, username):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return search_user_res
        user_dn = search_user_res["distinguishedName"]
        modify_res = conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, ["514"])]})
        return modify_res

    def enable_user(self, conn, username):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return search_user_res
        user_dn = search_user_res["distinguishedName"]
        modify_res = conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, ["512"])]})
        return modify_res

    def search_group(self, conn, group_name):
        #SEARCHFILTER = f'(&(objectClass=group)(samaccountname={group_name}))'

        SEARCHFILTER = "(&(objectClass=group)(samaccountname=%s))" % (group_name)
        conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=SEARCHFILTER,
            search_scope=SUBTREE,
            attributes=['*'],
            paged_size=1000,
            generator=False
        )
        if len(conn.entries) == 1:
            return conn.entries
        return "group not exist"

    def add_user_to_group(self, conn, username, group_name):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return "user not exist"
        search_group_res = self.search_group(conn, group_name)
        if search_group_res == "group not exist":
            return "group not exist"
        user_dn = str(search_user_res['distinguishedName'])
        group_dn = str(search_group_res[0].distinguishedName)
        #print(user_dn)
        #print(group_dn)
        ad_add_members_to_groups(conn, user_dn, group_dn, fix=True)
        return (conn.result)['description']

    def remove_user_from_group(self, conn, username, group_name):
        if conn == False:
            return "bind failed"
        search_user_res = self.search_user(conn, username)
        if search_user_res == "user not exist":
            return "user not exist"
        search_group_res = self.search_group(conn, group_name)
        if search_group_res == "group not exist":
            return "group not exist"
        user_dn = str(search_user_res['distinguishedName'])
        group_dn = str(search_group_res[0].distinguishedName)
        #print(user_dn)
        #print(group_dn)
        ad_remove_members_from_groups(conn, user_dn, group_dn, fix=True)
        return (conn.result)['description']
