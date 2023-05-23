#from builtins import print

from flask import Flask, render_template, request, redirect, session, url_for
from config import Config
import subprocess
import datetime
from flask_session import Session
import pyodbc
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import winrm
import datetime
import ldap
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


app.config.from_object(Config)
Session(app)




sql_server = 'msdb-cl.rst.atlantis-pak.ru'
sql_base = 'adgr'
class LoginUser:
    def __init__(self, user, passwd):
        self.__ad_user = user
        self.__ad_pass = passwd

    def user_valid(self):
        if adds_work(self.__ad_user,self.__ad_pass).get_usr_in_gr(self.__ad_user,'Администраторы домена'):
            return {'valid': True, 'data': [self.__ad_user, self.__ad_pass]}
        else:
            return {'valid': False, 'data': [self.__ad_user]}

class adds_work:
    def __init__(self,username, password):
        self.ad = ldap.initialize('ldap://rst.atlantis-pak.ru')
        self.ad.protocol_version = ldap.VERSION3
        self.__user = username
        self.__passwd = password
        self.base = 'DC=rst,DC=atlantis-pak,DC=ru'
        self.scope = ldap.SCOPE_SUBTREE
        # {'valid': True, 'data': search_base}
    def get_ad_groups(self):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            filter = '(&(objectClass=group))'
            attrs = ['name', 'sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            search_base = []
            for result in results:
                if result[0]:
                    for i in result:
                        if isinstance(i, dict):
                            search_base.append(dict(dn=result[0],name=i['name'][0].decode("utf-8"), sAMAccountName=i['sAMAccountName'][0].decode("utf-8")))
            return {'valid': True, 'data': search_base}
        except Exception as error_log:
            print(error_log)
            return {'valid': False,'data': error_log}

    def get_ad_users(self):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            filter = '(&(objectCategory=person)(objectClass=user))'
            attrs = ['name', 'sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            search_base = []

            for result in results:
                if result[0]:
                    for i in result:
                        if isinstance(i, dict):
                            search_base.append(dict(dn=result[0],name=i['name'][0].decode("utf-8"), sAMAccountName=i['sAMAccountName'][0].decode("utf-8")))
            return {'valid': True, 'data': search_base}
        except Exception as error_log:
            print(error_log)
            return {'valid': False,'data': error_log}
    def get_one_user(self, user):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            filter = '(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))'.format(user)
            attrs = ['name', 'sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            search_base = []
            for result in results:
                if result[0]:
                    for i in result:
                        if isinstance(i, dict):
                            search_base = dict(dn=result[0], name=i['name'][0].decode("utf-8"),sAMAccountName=i['sAMAccountName'][0].decode("utf-8"))

            return {'valid': True, 'data': search_base}
        except Exception as error_log:
            print(error_log)
            return {'valid': False,'data': error_log}
    def get_one_group(self, group):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            filter = '(&(objectCategory=group)(sAMAccountName={}))'.format(group)
            attrs = ['name', 'sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            search_base = []
            for result in results:
                if result[0]:
                    for i in result:
                        if isinstance(i, dict):
                            search_base = dict(dn=result[0], name=i['name'][0].decode("utf-8"),sAMAccountName=i['sAMAccountName'][0].decode("utf-8"))

            return {'valid': True, 'data': search_base}
        except Exception as error_log:
            print(error_log)
            return {'valid': False,'data': error_log}
    def dell_user_in_group(self, user, group):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            group_dn = self.get_one_group(group)
            user_dn = self.get_one_user(user)
            user_dn = bytes("{}".format(user_dn['dn']), 'utf-8')
            self.ad.modify_s(
                group_dn['dn'], [
                    (ldap.MOD_DELETE, 'member', [user_dn],)],
            )

            return {'valid': True, 'data':'deleted'}
        except ldap.UNWILLING_TO_PERFORM:
            print("no in group")
            return {'valid': False, 'data':'not_in_group'}
        except Exception as error_log:
            print(error_log)
            return {'valid': False, 'data':['error',error_log]}
    def add_user_in_group(self, user, group):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            group_dn = self.get_one_group(group)
            user_dn = self.get_one_user(user)
            user_dn = bytes("{}".format(user_dn['dn']), 'utf-8')
            self.ad.modify_s(
                group_dn['dn'], [
                    (ldap.MOD_ADD, 'member', [user_dn],)],
            )

            return {'valid': True, 'data':'added'}
        except Exception as error_log:
            print(error_log)
            return {'valid': False, 'data':['error',error_log]}
    def get_usr_in_gr(self, user, group):
        try:
            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            group = self.get_one_group(group)
            filter = '(&(objectClass=user)(memberof={}))'.format(group['data']['dn'])
            attrs = ['sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            value = False

            for result in results:
                if result[0]:
                    if user == result[1]['sAMAccountName'][0].decode("utf-8"):
                        value = True
            return value
        except Exception as error_log:
            print(error_log)
            return False
    def get_all_usr_in_gr(self, group):
        try:

            self.ad.simple_bind_s('RST\\' + self.__user, self.__passwd)
            group = self.get_one_group(group)
            filter = '(&(objectClass=user)(memberof={}))'.format(group['data']['dn'])
            attrs = ['sAMAccountName']
            results = self.ad.search_s(self.base, self.scope, filter, attrs)
            search_base = [result[1]['sAMAccountName'][0].decode("utf-8") for result in results if result[0]]
            return {'valid': True, 'data': search_base}
        except Exception as error_log:
            print(error_log)
            return {'valid': False, 'data':['error',error_log]}

class InputBtnReMail:
    def __init__(self):
        self.btn_console = request.form.get('btn_console')
        self.field_for_mantis_req = request.form.get('field_for_mantis_req')
        self.field_for_mail_sent_to = request.form.get('field_for_mail_sent_to')
        self.field_for_mail_to_bbc = [item for item in request.form.getlist('field_for_mail_to_bbc') if item]
        self.checked_remail = request.form.getlist('checked_remail')
        self.date_for_start_redirection = request.form.get('date_for_start_redirection')
        self.date_for_end_redirection = request.form.get('date_for_end_redirection')
        self.date_for_start = datetime.datetime.strptime(request.form.get('date_for_start_redirection'), "%Y-%m-%dT%H:%M")
        self.date_for_end = datetime.datetime.strptime(request.form.get('date_for_end_redirection'), "%Y-%m-%dT%H:%M")
    @staticmethod
    def error_out(text):
        output_log_temp, output_log = dict(), dict()
        output_log_temp["Ошибка"] = {
            "Скрипт вернул:": text,
        }
        output_log["Ошибка"] = output_log_temp
        return output_log
    def test_mantis(self, list):
        temp = []
        for item in list:
            if item[1] == self.field_for_mantis_req:
                temp.append(item[0])
        if len(temp) > 0:
            return True, temp
        return False, False

    def result(self):
        return {'name':self.field_for_mantis_req,'SentTo':self.field_for_mail_sent_to,'BlindCopyTo':self.field_for_mail_to_bbc,'ActivationDate':self.date_for_start_redirection,'ExpiryDate':self.date_for_end_redirection}

    def test_input_remail(self):
        if self.field_for_mantis_req and self.field_for_mail_sent_to and self.field_for_mail_to_bbc != []:
            return True
        return False

class ExchangePowershell:
    def __init__(self, server, username, password):
        self.server = server
        self.__username = username
        self.__password = password
        self.wsman = WSMan(server=self.server, username=self.__username, password=self.__password, port=80, path="PowerShell", ssl=False, auth="kerberos", cert_validation=False)
    def exchange_powershell_add_rule(self,rule_mantis,date_s,date_e,from_s,Bcc,comments):
        with self.wsman, RunspacePool(self.wsman, configuration_name="Microsoft.Exchange") as pool:
            ps = PowerShell(pool)
            print(rule_mantis,date_s,date_e,from_s,Bcc,comments)
            ps.add_cmdlet("new-TransportRule").add_parameter("-name", rule_mantis).add_parameter("-ActivationDate", date_s).add_parameter("-ExpiryDate", date_e).add_parameter("-SentTo",from_s).add_parameter("-BlindCopyTo", Bcc).add_parameter("-Comments", comments)
            output = ps.invoke()
            if output != []:
                return True
            return False

    def exchange_powershell_dell_rule(self,rule_mantis):
        try:
            with self.wsman, RunspacePool(self.wsman, configuration_name="Microsoft.Exchange") as pool:
                ps = PowerShell(pool)

                if len(rule_mantis) > 1:
                    for item in rule_mantis:
                        ps.add_cmdlet("Remove-TransportRule").add_parameter("-Identity", item).add_parameter('Confirm', False)
                        ps.add_statement()
                else:
                    ps.add_cmdlet("Remove-TransportRule").add_parameter("-Identity", rule_mantis[0]).add_parameter('Confirm',
                                                                                                         False)

                output = ps.invoke()

                return True
        except Exception as e:
            return e
    def exchange_powershell_get_rule(self,rule_mantis):
        with self.wsman, RunspacePool(self.wsman, configuration_name="Microsoft.Exchange") as pool:
            ps = PowerShell(pool)
            print(rule_mantis)
            ps.add_cmdlet("get-TransportRule").add_parameter("-Identity", rule_mantis)
            output = ps.invoke()
            if output != []:
                return True
            return False

class scripts_worker:
    def __init__(self, server, username, password):
        self.server = server
        self.__username = username
        self.__password = password
    def cmd(self, scripts):
        try:
            prot = winrm.protocol.Protocol(
                server_cert_validation="ignore",
                endpoint="http://{}:5985/wsman".format(self.server),
                transport="ntlm",
                username='RST\\' + self.__username,
                password=self.__password,
            )

            shell = prot.open_shell()
            command = prot.run_command(shell, scripts)
            out, err, status = prot.get_command_output(shell, command)
            prot.close_shell(shell)
            #return out, err, status
            if out:
                return out

            return 'Empty'

        except Exception as sent_err:
            for_log = 'Exception Problem function cmd_re Error: \n{}'.format(sent_err)
            return for_log
    def powershell_sc(self, script):
        try:
            wsman = WSMan(server=self.server, username=self.__username, password=self.__password, port=5985, path="wsman", ssl=False,
                          auth="kerberos", server_cert_validation="ignore", encryption="always")
            with wsman, RunspacePool(wsman) as pool:
                ps = PowerShell(pool)
                ps.add_script(script)
                ps.invoke(["string", 1])
                print(ps.streams.debug)
                return ps.output

        except Exception as sent_err:
            for_log = 'Exception Problem function powershell_re Error: \n{}'.format(sent_err)
            return for_log

class sql_table_work:

    def __init__(self, server, datebase, table):
        a = subprocess.run(
            'cat /etc/serv/secret/nginx_log.txt | openssl enc -aes-256-cbc -md sha512 -a -d -pbkdf2 -iter 100000 -salt -pass pass:for_sql_log!',
            shell=True, stdout=subprocess.PIPE)
        b = subprocess.run(
            'cat /etc/serv/secret/nginx_pwd.txt | openssl enc -aes-256-cbc -md sha512 -a -d -pbkdf2 -iter 100000 -salt -pass pass:for_sql_pwd!',
            shell=True, stdout=subprocess.PIPE)
        username = a.stdout.decode("utf-8").replace("\n", '')
        password = b.stdout.decode("utf-8").replace("\n", '')
        self.__table = table
        self.__str = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=' +f'{server};DATABASE={datebase};UID={username};PWD={password};'

    def get_data_tabel_dict(self):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            colm_name = []
            for row in cursor.columns(table="{}".format(self.__table)):
                colm_name.append(row.column_name)
            results = []
            cursor.execute("SELECT * FROM {}".format(self.__table))
            for row in cursor.fetchall():
                results.append(dict(zip(colm_name, row)))
            conn.commit()
            return results
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def get_data_tabel_colm_name(self):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            colm_name = []
            for row in cursor.columns(table="{}".format(self.__table)):
                colm_name.append(row.column_name)

            conn.commit()
            if colm_name == []:
                raise "Empty value, no data in list"
            return colm_name
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def get_data_tabel_colm_data(self):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            farm_colm = cursor.execute("SELECT * FROM {}".format(self.__table))
            colm_data = farm_colm.fetchall()
            conn.commit()
            return colm_data
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def update_data_table(self, update_col_name, update_col_data, new_update_col_name, new_update_col_data):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            update_query = "UPDATE {} SET {}='{}' WHERE {}='{}'".format(self.__table, new_update_col_name, new_update_col_data, update_col_name, update_col_data)
            cursor.execute(update_query)
            conn.commit()
            return True
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def delete_data_table(self, del_colum_name, del_colum_date):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            update_query = "DELETE FROM {} WHERE {} = '{}'".format(self.__table, del_colum_name, del_colum_date)
            cursor.execute(update_query)
            conn.commit()
            return True
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def insert_data_table(self, *del_colum_data):
        try:
            temp = ''
            for item in del_colum_data:
                temp += f"'{item}',"
            temp = temp[:-1]
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            update_query = 'INSERT INTO {} VALUES({});'.format(self.__table,temp)
            print(update_query)
            cursor.execute(update_query)
            conn.commit()
            return True
        except Exception as sent_err:
            return ['Error', [sent_err]]

    def search_data_tabel_colm(self, search_colm, search_data):
        try:
            conn = pyodbc.connect(self.__str)
            cursor = conn.cursor()
            farm_colm = cursor.execute("SELECT * FROM {} WHERE {}='{}'".format(self.__table, search_colm, search_data))
            colm_data = farm_colm.fetchall()
            conn.commit()
            return colm_data
        except Exception as sent_err:
            return ['Error', [sent_err]]

class InputBtn:
    def __init__(self):
        self.farm_rds = 'test_farm'
        self.farm_broker = 'brokers'
        self.scada_client = 'mscada_client'
        self.scada_server = 'mscada_server'
        self.__btn_value = request.form.get('btn_console')
        self.__checked_srv = request.form.getlist('checked_server')
        self.checkbox_script = request.form.get('checkbox_script')
        self.checkbox_language = request.form.get('checkbox_language')
        self.field_for_text_script = request.form.getlist('field_for_text_script')
        self.script1 = '''
                                try {
                                 Get-Service Spooler | Restart-Service 
                                 Get-Service Spooler | Out-String -Stream
                                }
                                catch {
                                 $Error | Out-String -Stream
                                }
                                                '''
        start_sc = '''
                                        try {
                                     '''
        drop_sc = '''rwinsta {}'''.format(self.field_for_text_script[0])
        end_sc = '''
                                    }
                                    catch {
                                     $Error | Out-String -Stream
                                    }

                                                        '''
        self.script2 = start_sc + drop_sc + end_sc
        self.script3 = '''
        try {
         restart-computer -force

        }
        catch {
         $Error | Out-String -Stream
        }
                        '''
        self.script_get_rdp_sess = '''
        $a = query session
        $b = @()
        $c=@()
        foreach($a0 in $a){
        if($a0 -match "rdp-tcp#*"){
        $b = @()
        $a0 = $a0 -split " "
        foreach($a01 in $a0){
        if($a01 -notlike ''){$b +=$a01}
        }
        $c += $b[1],$b[2]
        }
        }
        $c
        '''
        self.script_1074 = '''
                                    Get-WinEvent -LogName "system" -FilterXPath "*[System[EventID=1074]]" | ?{$_.TimeCreated -ge (get-date).adddays(-14)} | fl TimeCreated,Message | Out-String -Stream  
                                     
                                    '''
        self.script_41 = '''
                                    $event = 41
                                    $a = Get-WinEvent -LogName "system" -FilterXPath "*[System[EventID=41]]" | ?{$_.TimeCreated -ge (get-date).adddays(-14)}
                                    if($a){
                                    foreach($a0 in $a){
                                    $date123 =$a0.TimeCreated
                                    $date123 = '{0:dd:MM:yyyy HH:mm}' -f $date123
                                    $Message = 'Критическое выключение'
                                    $Message = "Код события " + "$event" + ' ' + $Message
                                    $date123
                                    $Message
                                    }}
                                    '''
        self._field_for_message_to_server = request.form.getlist('field_for_message_to_server')
    def test_checked_srv(self):
        if self.__checked_srv:
            return self.__btn_value, self.__checked_srv
        else:
            return False
    def test_all(self):
        return self.__btn_value, self.__checked_srv,self.checkbox_script,self.checkbox_language,self.field_for_text_script

class WorkProcess(InputBtn):
    @staticmethod
    def text_status(status):
        if status == 'Active':
            return 'Reserve'
        return 'Active'
    @staticmethod
    def log_in_dict(log):
        temp_date = []
        temp1_data = []
        for i in range(len(log)):
            if i % 2 == 0:
                temp_date.append(log[i])
            else:
                temp1_data.append(log[i])
        info = dict(zip(temp_date, temp1_data))
        temp = []
        for i, j in info.items():
            if '65' not in i:
                temp.append( f"Пользователь: {(i.replace('<S>', '')).replace('</S>', '')}.   ID: {(j.replace('<S>', '')).replace('</S>', '')}")
        return temp
    @staticmethod
    def log_in_dict_id(log):
        temp_date = []
        temp1_data = []
        for i in range(len(log)):
            if i % 2 == 0:
                temp_date.append(log[i])
            else:
                temp1_data.append(log[i])
        info = dict(zip(temp_date, temp1_data))
        temp = []
        for i, j in info.items():
            if '65' not in i:
                temp.append([(i.replace('<S>', '')).replace('</S>', ''),(j.replace('<S>', '')).replace('</S>', '')])
        return temp
    @staticmethod
    def error_out(text):
        output_log_temp, output_log = dict(), dict()
        output_log_temp["Ошибка"] = {
            "Скрипт вернул:": text,
        }
        output_log["Ошибка"] = output_log_temp
        return output_log

    def btn_change_status(self, server_name):
        output_log_temp, output_log = dict(), dict()
        data_base = sql_table_work(sql_server, sql_base, self.farm_rds)
        for items in data_base.get_data_tabel_colm_data():
            for item in server_name:
                if items[0] == item:
                    server_status = self.text_status(items[2])
                    output_log_temp["{}".format(item)] = {
                                "Статус исполнения:": data_base.update_data_table('serv', item, 'stat', server_status),
                                "Новый статус сервера:": server_status,
                                            }

        output_log["btn_change_status"] = output_log_temp
        print(output_log)
        return output_log
    def btn_reboot(self,server_name):
        if request.form.get('date_reboot'):
            output_log_temp, output_log = dict(), dict()
            date_reboot = datetime.datetime.strptime(request.form.get('date_reboot'), "%Y-%m-%dT%H:%M")

            for item in server_name:

                if item.lower() == 'ts61-1b' or item.lower() == 'ts61-2b':
                    temp_base = self.farm_broker
                elif item.lower() == 'rst-mscada-cl1' or item.lower() == 'rst-mscada-cl2':
                    output_log_temp["{}".format(item.lower())] = {
                        "Статус исполнения:": 'Запланировать перезагрузку для серверов СКАДА не возможно',

                    }
                    continue
                elif 'mscada-l' in item.lower() or 'shl-ms-lsm' in item.lower():
                    temp_base = self.scada_client
                    print(temp_base)
                elif 'ts61-' in item.lower():
                    temp_base = self.farm_rds
                    print(temp_base)

                output_log_temp["{}".format(item.lower())] = {
                    "Статус исполнения:": sql_table_work(sql_server, sql_base, temp_base).update_data_table('serv', item,
                                                                                                       'date_n',
                                                                                                       date_reboot),
                    "Новая дата перезагрузки сервера:": date_reboot,
                }

            output_log["btn_reboot"] = output_log_temp
            return output_log
        else:
            return self.error_out('Нет даты для перезагрузки')
    def btn_sent_sc(self, server_name, username, password):
        output_log_temp, output_log = dict(), dict()
        for items in server_name:
            server = items +".rst.atlantis-pak.ru"
            if self.checkbox_script == 'script1' and not self.checkbox_language:
                output_log_temp["{}".format(items)] = {
                    "Скрипт вернул:": [(item.replace('<S>','')).replace('</S>','') for item in scripts_worker(server, username, password).powershell_sc(self.script1)],
                    "Отправлен скрипт: ": self.script1,
                }
            elif self.checkbox_script == 'script2' and not self.checkbox_language:
                output_log_temp["{}".format(items)] = {
                    "Скрипт вернул:": [(item.replace('<S>','')).replace('</S>','') for item in scripts_worker(server, username, password).powershell_sc(self.script2)],
                    "Отправлен скрипт:": self.script2,
                }
            elif self.checkbox_script == 'script3' and not self.checkbox_language:
                output_log_temp["{}".format(items)] = {
                    "Скрипт вернул:": [(item.replace('<S>','')).replace('</S>','') for item in scripts_worker(server, username, password).powershell_sc(self.script3)],
                    "Отправлен скрипт:": self.script3,
                }
            elif self.checkbox_language and not self.checkbox_script:
                if self.checkbox_language == "cmd":
                    temp_ooutput = scripts_worker(server, username, password).cmd(self.field_for_text_script[0])
                    try:
                        temp_ooutput = (temp_ooutput.decode('utf-8', errors='ignore')).split('\r\n')
                    except:
                        temp_ooutput = ['',temp_ooutput]

                    output_log_temp["{}".format(items)] = {
                        "Скрипт вернул:": temp_ooutput,
                        "Отправлен скрипт:": self.field_for_text_script[0],
                    }

                elif self.checkbox_language == "powershell":
                    body_start = '''
                                try {
                                                '''
                    body_mid_command = self.field_for_text_script[0]
                    body_end = '''
                                }
                                catch {

                                $Error | Out-String -Stream
                                }
                                
                                
                                '''
                    if '| Out-String -Stream' not in body_mid_command:
                        body_mid_command += ' | Out-String -Stream'
                    final = body_start + body_mid_command + body_end
                    output_log_temp["{}".format(items)] = {
                        "Скрипт вернул:":   [(item.replace('<S>','')).replace('</S>','') for item in scripts_worker(server, username, password).powershell_sc(final)],
                        "Отправлен скрипт:": self.field_for_text_script[0],
                    }
            elif self.checkbox_script and self.checkbox_language:
                error = self.error_out("е")
                error["Ошибка"]["Ошибка"] = {
                    "Скрипт вернул:": 'Выбрано несколько действий',
                    "Отправлен скрипт:": "Выбирите язык или скрипт"
                }
                return error
            else:
                error = self.error_out("е")
                error["Ошибка"]["Ошибка"] ={
                    "Скрипт вернул:": 'Не выбрано действие',
                    "Отправлен скрипт:": "Выбирите язык или скрипт"
                }
                return error

        output_log["btn_sent_script"] = output_log_temp
        return output_log
    def btn_statistics(self, server_name, username, password):
        output_log_temp, output_log = dict(), dict()
        for items in server_name:
            server = items + ".rst.atlantis-pak.ru"
            output_log_temp["{}".format(items)] = {
                    "Запланированная перезагрузка": [(item.replace('<S>', '')).replace('</S>', '') for item in
                                      scripts_worker(server, username, password).powershell_sc(self.script_1074)],
                    "Не запланированная перезагрузка": [(item.replace('<S>', '')).replace('</S>', '') for item in
                                      scripts_worker(server, username, password).powershell_sc(self.script_41)],
                    "Сессии сервера": self.log_in_dict(scripts_worker(server, username, password).powershell_sc(self.script_get_rdp_sess)),
                }

            output_log["btn_statistics"] = output_log_temp
        return output_log
    def btn_reset_session(self, server_name, username, password):
        output_log_temp, output_log = dict(), dict()
        for items in server_name:
            server = items + ".rst.atlantis-pak.ru"
            sc_worck = scripts_worker(server, username, password)
            temp_sess =[]
            for item in self.log_in_dict_id(sc_worck.powershell_sc(self.script_get_rdp_sess)):
                script_drop_sess = '''
                rwinsta {}
                '''.format(item[1])
                sc_worck.powershell_sc(script_drop_sess)
                temp_sess.append("{} - отключен".format(item[0]))
            output_log_temp["{}".format(items)] = {
                "Сессии сервера": temp_sess,
            }

        output_log["btn_reset_session"] = output_log_temp
        return output_log
    def btn_sent_notify(self, server_name, username, password):
        output_log_temp, output_log = dict(), dict()
        script_message_all = ''' 
                                msg * "{}"
                                '''.format(self._field_for_message_to_server[0])

        for items in server_name:
            server = items + ".rst.atlantis-pak.ru"
            sc_worck = scripts_worker(server, username, password)
            sc_worck.powershell_sc(script_message_all)

            output_log_temp["{}".format(items)] = {
                "Отправлено сообщение:": self._field_for_message_to_server,
                "Сессии сервера": [item[0] for item in self.log_in_dict_id(sc_worck.powershell_sc(self.script_get_rdp_sess))],
            }

            output_log["btn_reset_session"] = output_log_temp
            return output_log

class web_log:
    def __init__(self):
        self.log_date = log_date
    def parse_web_log(self):
        pass

@app.route('/farm_test', methods=['GET', 'POST'])
def farm_test():
    action = "False"
    action = session.get('True', None)
    import datetime
    if action == "True":
        farm_tab_rds = 'test_farm'
        farm_tab_brokers = 'brokers'
        log_date = [['Добро пожаловать','в консоль управления терминальными серверами!','В этом окне будет содержаться краткий перечень возможностей.',
                    'Функционал кнопок:'],['Statistics - Вывод информации о событиях в журналах на ТС(41,1074), а так же перечень пользователей на сервере',
                    'Change_stats - включает/выключает возможность подключения пользователей к серверу',
                    'Notify - рассылка сообщений пользователям сервера',
                    'reset sess - сброс сессий пользователей на сервере',
                    'Script_sent - отправка скриптов на сервера, необходимо выбрать скриптовый язык (Есть перечень стандартных скриптов)',
                    'Reboot - перезагрузка серверов(невозможно перезагрузить сервер находящийся в работе, так же для подтверждения действий нужно отметить чекбокс)'],
                    ['Важно понимать, что все кнопки работают ко ВСЕМ отмеченым серверам чекбоксами']]
        username = "_yakushev"
        password = "71032ethement*()!"
        metode = 'GET'
        if request.method == 'POST':
            test_checked_srv = InputBtn().test_checked_srv()

            if test_checked_srv:
                if test_checked_srv[0] == "btn_change_status":
                    log_date = WorkProcess().btn_change_status(test_checked_srv[1])
                elif test_checked_srv[0] == "btn_reboot":
                    log_date =WorkProcess().btn_reboot(test_checked_srv[1])
                elif test_checked_srv[0] == "btn_statistics":
                    log_date = WorkProcess().btn_statistics(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_sent_notify":
                    log_date = WorkProcess().btn_sent_notify(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_reset_session":
                    log_date = WorkProcess().btn_reset_session(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_sent_script":
                    log_date = WorkProcess().btn_sent_sc(test_checked_srv[1], username, password)
            else:
                log_date = WorkProcess().error_out("Не выбран ни один сервер")

            metode = 'POST'

        sql_date_rds = sql_table_work(sql_server, sql_base, farm_tab_rds)
        sql_date_brokers = sql_table_work(sql_server, sql_base, farm_tab_brokers)
        col_rds_in = sql_date_rds.get_data_tabel_colm_name()
        table_rds_data = sql_date_rds.get_data_tabel_colm_data()
        col_rds = ["Имя сервера","Статус","Дата перезагрузки","Дата след. перезагрузки","Сессии","IP-адрес"]
        table_broker_data = sql_date_brokers.get_data_tabel_colm_data()
        col_broker = ["Имя сервера", "Статус", "Дата перезагрузки", "Дата след. перезагрузки", "Старые ТС", "IP-адрес","123"]
        farm_name = [item[1] for item in table_rds_data]
        farm_name = list(set(farm_name))
        sorted(farm_name)




        return render_template(
            'rds.html',
            col_rds=col_rds,
            col_broker=col_broker,
            table_rds_data=table_rds_data,
            table_broker_data=table_broker_data,
            farm_name=farm_name,
            len=len(col_rds_in),
            log_date=log_date,
            metode=metode,


        )
    else:

        return render_template(
            'error_form.html',
        )

@app.route('/mscada_test', methods=['GET', 'POST'])
def mscada_test():
    action = "False"
    action = session.get('True', None)
    import datetime
    if action == "True":
        sql_server = 'msdb-cl.rst.atlantis-pak.ru'
        sql_base = 'adgr'
        mscada_client = 'mscada_client'
        mscada_server = 'mscada_server'
        log_date = [['Добро пожаловать','в консоль управления серверами MSCADA!','В этом окне будет содержаться краткий перечень возможностей.',
                    'Функционал кнопок:'],['Statistics - Вывод информации о событиях в журналах на ТС(41,1074), а так же перечень пользователей на сервере',

                    'Notify - рассылка сообщений пользователям сервера',
                    'reset sess - сброс сессий пользователей на сервере',
                    'Script_sent - отправка скриптов на сервера, необходимо выбрать скриптовый язык (Есть перечень стандартных скриптов)',
                    'Reboot - перезагрузка серверов(невозможно перезагрузить сервер находящийся в работе, так же для подтверждения действий нужно отметить чекбокс)'],
                    ['Важно понимать, что все кнопки работают ко ВСЕМ отмеченым серверам чекбоксами']]
        username = "_yakushev"
        password = "71032ethement*()!"
        metode = 'GET'
        if request.method == 'POST':
            test_checked_srv = InputBtn().test_checked_srv()

            if test_checked_srv:
                if test_checked_srv[0] == "btn_reboot":
                    log_date =WorkProcess().btn_reboot(test_checked_srv[1])
                elif test_checked_srv[0] == "btn_statistics":
                    log_date = WorkProcess().btn_statistics(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_sent_notify":
                    log_date = WorkProcess().btn_sent_notify(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_reset_session":
                    log_date = WorkProcess().btn_reset_session(test_checked_srv[1], username, password)
                elif test_checked_srv[0] == "btn_sent_script":
                    log_date = WorkProcess().btn_sent_sc(test_checked_srv[1], username, password)
            else:
                log_date = WorkProcess().error_out("Не выбран ни один сервер")

            metode = 'POST'
        sql_date_mscada_client = sql_table_work(sql_server, sql_base, mscada_client)
        sql_date_mscada_server = sql_table_work(sql_server, sql_base, mscada_server)
        col_mscada_client_count = sql_date_mscada_client.get_data_tabel_colm_name()
        table_mscada_client_data = sql_date_mscada_client.get_data_tabel_colm_data()
        col_mscada_client = ["Имя сервера", "IP", "Дата пер.", "Дата след. пер.", "ИД ТК", "Пользователь","IP"]
        table_mscada_server_data = sql_date_mscada_server.get_data_tabel_colm_data()
        col_mscada_server = ["Имя сервера", "IP", "mps", "masterscada", "nrsvr", "Пользователь", "Диск С:"]


        return render_template(
            'mscada.html',
            col_mscada_client=col_mscada_client,
            col_mscada_server=col_mscada_server,
            table_mscada_client_data=table_mscada_client_data,
            table_mscada_server_data=table_mscada_server_data,
            len=len(col_mscada_client_count),
            log_date=log_date,
            metode=metode,
        )

@app.route('/add_group_test', methods=['GET', 'POST'])
def add_group_test():
    import datetime
    action = "False"
    action = session.get('True', None)

    if action == "True":
        log_date =[['Добро пожаловать',
        'в консоль для временного добавления пользователей в группы!',
            'В этом окне будет содержаться краткий перечень возможностей.',
            'Краткое описание:'],['- "Проверка пользователей" - позволяет протестировать введенных в поле "Пользователь" данные. В окне статистики выводится перечень верно и неверно введенных данных.',
             '- "Добавить пользователей" - позволяет добавить данные в базу для временного нахождения в нужной группе. К данной кнопке отноятся чекбоксы:',
             '   - "На один день раньше" (установлена автоматически) - позволяет добавить на день раньше указанного срока',
             '   - "Быстрое добавление" (неустановлена автоматически) - после записи в базу, запускается скрипт добавления в группу',
             '   - "Постоянный доступ" (неустановлена автоматически) - конечная дата автоматически меняется на дату + 9999 дней',
            '- "Изменить прибывание в группе пользователя" - позволяет менять даты присутствия в группе для пользователя или пользователей (При изменению даты по обращению, в поле "обращения" необходимо ввеси его номер)',
             '- "Изменить прибывание в группе пользователя по обращению" - позволяет менять даты присутствия в группе по номеру обращения (будут изменены все даты по обращению, не берется в расчет группа пребывания)',
             '- "Удалить пользователя из таблицы" - позволяет удалить пользователей из таблицы и из группы соответственно, работает с перечнем пользователей.',
             '- "Справка" - вызов справки'],['Примечание.','При неправльном вводе логина информация будет выведена в окно статистики ']]
        ad_username = session.get('ad_username', None)
        ad_password = session.get('ad_password', None)
        print(ad_username,ad_password)
        date = datetime.date.today()
        time_s = datetime.time(00, 00)
        time_e = datetime.time(23, 59)
        data_min = datetime.datetime.combine(date, time_s)
        data_s = datetime.datetime.combine(date, time_s)
        data_e = datetime.datetime.combine(date, time_e)

        return render_template(
            'add_group.html',
            log_date=log_date,

            data_s=data_s,
            data_e=data_e,
            data_min=data_min,
            old_input_group="VPN",
        )

@app.route('/remail_test', methods=['GET', 'POST'])
def remail_test():
    import datetime
    action = "False"
    action = session.get('True', None)
    if action == "True":
        date = datetime.date.today()
        time_s = datetime.time(00, 00)
        time_e = datetime.time(23, 59)
        metode = 'GET'
        data_min = datetime.datetime.combine(date, time_s)
        data_s = datetime.datetime.combine(date, time_s)
        data_e = datetime.datetime.combine(date, time_e)
        sql_server = 'msdb-cl.rst.atlantis-pak.ru'
        sql_base = 'adgr'
        sql_base_remail = 'exchange_rule'
        sql_date_remail = sql_table_work(sql_server, sql_base, sql_base_remail)
        col_sql_date_remail = sql_date_remail.get_data_tabel_colm_name()
        table_sql_date_remail = sql_date_remail.get_data_tabel_colm_data()

        log_date = [['Добро пожаловать ','в консоль установки/удаления временной переадресации почты!', 'Функционал кнопок:'],
                    ['ADD - Добавляет переадресацию для одного и более пользователей','Del - Удаляет правила переадресации','Show - Показывает правила переадресации'],['БУДЬТЕ ВНИМАТЕЛЬНЫ!!']]
        if request.method == 'POST':
            metode = 'POST'
            remail_btn = InputBtnReMail()
            remail_data = remail_btn.result()
            username = "_yakushev"
            password = "71032ethement*()!"
            server = 'exch-cl2.rst.atlantis-pak.ru'
            scripts_worker_data = ExchangePowershell(server, username, password)
            output_log_temp, output_log = dict(), dict()
            if remail_btn.btn_console == 'btn_add_redirection':
                if remail_btn.test_input_remail():
                    bool_test_sql, data_test_sql = remail_btn.test_mantis(table_sql_date_remail)
                    if bool_test_sql:
                        for i in data_test_sql:
                            sql_date_remail.delete_data_table('rule_id', i)
                    test_sql = sql_date_remail.insert_data_table(remail_btn.field_for_mantis_req,remail_btn.field_for_mail_sent_to,remail_btn.field_for_mail_to_bbc[0],remail_btn.date_for_start,remail_btn.date_for_end,username)
                    test_exchange = scripts_worker_data.exchange_powershell_add_rule(remail_data['name'],remail_data['ActivationDate'],remail_data['ExpiryDate'],remail_data['SentTo'],remail_data['BlindCopyTo'],username)
                    if not test_sql:
                        log_date = remail_btn.error_out(test_sql)
                    elif not test_exchange:
                        log_date = remail_btn.error_out('Не удалось добавить правило на сервер электронной почты')
                    else:
                        output_log_temp["btn_add_redirection"] = {"Добавление переадресации": {
                                    "Скрипт вернул:": 'По обращению {} добавлена переадресация с {} на {} на период с {} до {} пользователем {}'.format(remail_btn.field_for_mantis_req,remail_btn.field_for_mail_sent_to,remail_btn.field_for_mail_to_bbc[0],remail_btn.date_for_start,remail_btn.date_for_end,username),

                                }}

                        log_date = output_log_temp



                else:
                    log_date = remail_btn.error_out('Не заполнено одно или несколько полей, исправьте проблему и повторите попытку')

            elif remail_btn.btn_console == 'btn_dell_redirection':
                checked_rule = remail_btn.checked_remail
                if checked_rule != []:
                    temp_dell_rule = []
                    for chek in checked_rule:
                        for item in table_sql_date_remail:
                            if int(chek) == item[0]:
                                temp_dell_rule.append(item)
                    print(temp_dell_rule)
                    if temp_dell_rule !=[]:
                        for item in temp_dell_rule:
                            print(item)
                            test_exchange = True
                            test_sql = sql_date_remail.delete_data_table('rule_id', item[0])
                            print(not test_exchange or not test_sql)
                            if not test_exchange or not test_sql:
                                output_log_temp["Ошибка"] = {
                                    "Скрипт вернул:": "Ошибка при удалении правила. SQL вернул: {} \nPowershell вернул: {}".format(test_sql, test_exchange),

                                }


                            else:
                                output_log_temp["Удаление переадресации {}".format(item[1])] = {
                                    "Скрипт вернул:": "По обращению {} удалено правило с ИД {}".format(item[1], item[0]),

                                }
                        scripts_worker_data.exchange_powershell_dell_rule([item[1] for item in temp_dell_rule])
                        output_log["btn_add_redirection"] = output_log_temp
                        log_date = output_log
                    else:
                        log_date = remail_btn.error_out('Выбранное правило не существует, обновите страницу')
                else:
                    log_date = remail_btn.error_out('Не выбрано ни одно правило')
            elif remail_btn.btn_console == 'btn_show_base_redirection':
                metode = 'GET'

            print(log_date)


        table_sql_date_remail = sql_date_remail.get_data_tabel_colm_data()
        test = []
        for item in table_sql_date_remail:
            temp = []
            for i in item:
                if type(i) is datetime.datetime and i < data_s:
                    temp.append('!'+str(i))
                else:
                    temp.append(i)
            test.append(temp)
        datetime_in = '!1900-01-01 00:00:00'
        column_re = ['','Обращение','С кого','Кому','Начало','Конец','Добавил']
        return render_template(
            'remail.html',
            return_colm=test,
            len=len(col_sql_date_remail),
            log_date=log_date,
            metode=metode,
            data_s=data_s,
            data_e=data_e,
            datetime_in=datetime_in,
            column_re=column_re
        )

@app.route('/ad_stat_test', methods=['GET', 'POST'])
def ad_stat_test():
    import datetime
    action = "False"
    action = session.get('True', None)
    if action == "True":
        sql_server = 'msdb-cl.rst.atlantis-pak.ru'
        sql_base = 'adgr'
        sql_base_ad_search = 'ADgroup1'
        # sql_date_ad_search = sql_table_work(sql_server, sql_base, sql_base_ad_search)
        # col_sql_date_ad_search = sql_date_ad_search.get_data_tabel_colm_name()
        # table_sql_date_ad_search = sql_date_ad_search.get_data_tabel_colm_data()

        return render_template(
            'ad_stat.html',
            log_date=log_date,
        )


@app.route('/mail_stat_test', methods=['GET', 'POST'])
def mail_stat_test():
    import datetime
    action = "False"
    action = session.get('True', None)
    if action == "True":
        sql_server = 'msdb-cl.rst.atlantis-pak.ru'
        sql_base = 'adgr'



        return render_template(
            'mail_stat.html',

        )

@app.route('/', methods=['GET', 'POST'])
def input_form():
    if request.method == 'POST':
        buttun = request.form.get('btn_console')
        if buttun == "input_button":
            testing = LoginUser(request.form.get('login_form'), request.form.get('password_form')).user_valid()
            if testing['valid']:
                session['ad_username'] = testing['data'][0]
                session['ad_password'] = testing['data'][1]
                session['True'] = "True"
                return redirect(url_for('farm_test'))
            else:
                return render_template(
                    'Error_log_pass.html',
                )
        return render_template(
            'input_form.html',

        )


    return render_template(
        'input_form.html',

    )


if __name__ == '__main__':
    app.run(host='10.1.23.54', port=5000)

