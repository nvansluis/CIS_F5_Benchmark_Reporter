#!/bin/python3
# -*- coding: utf-8 -*-
#
# CIS F5 Benchmark Reporter - Reports on compliancy with CIS Benchmark for F5
#
# Version: 0.4
# Last Modified: 21 March 2025
# Author: Niels van Sluis
#
# This Sample Software provided by the author is for illustrative
# purposes only which provides customers with programming information
# regarding the products. This software is supplied "AS IS" without any
# warranties and support.
#
# The author assumes no responsibility or liability for the use of the
# software, conveys no license or title under any patent, copyright, or
# mask work right to the product.
#
# The author reserves the right to make changes in the software without
# notification. The author also make no representation or warranty that
# such application will be suitable for the specified use without
# further testing or modification.
#-----------------------------------------------------------------------

import base64
import crypt
import datetime
import getopt
import platform
import re
import smtplib
import ssl
import subprocess
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#-----------------------------------------------------------------------
# User Options - Configure as desired
#-----------------------------------------------------------------------

# e-mail settings
port = 587
smtp_server = "smtp.example.com"
sender_email = "johndoe@example.com"
receiver_email = "johndoe@example.com"
login = "johndoe"
password = "mySecret"

# list containing trusted IP addresses and networks that have access to SNMP (control 6.1)
snmp_client_allow_list = [
    "127.0.0.0/8",
]

# set exceptions (add your own exceptions)
exceptions = {
    '2.1' : "Exception in place, because TACACS is used instead of RADIUS.",
    '2.2' : "Exception in place, because TACACS is used and there are two TACACS-servers present."
}

#-----------------------------------------------------------------------
# Implementation - Please do not modify
#-----------------------------------------------------------------------

benchmark_totals = {}
controls = {}
enabled_services = {}
hostname = platform.node()
software_build = None
software_edition = None
software_version = None
version = "v0.4"

class CIS:
    def __init__(self, control, description):
        self.control = control
        self.description = description
        self.setCorrectly = False
        self.comment = None
        self.setException = False
        self.exceptionText = None

class EnabledServices:
    def __init__(self, service, description, required_status, modules):
        self.service = service
        self.description = description
        self.required_status = required_status
        self.current_status = None
        self.modules = modules

class ControlFunctions:
    def __init__(self):
        pass

    def control_1_1_1(self):
        # 1.1.1 Ensure default password of root is not allowed (Automated)
        #
        # Open /etc/shadow file and check if hash matches the default root password.
        f = open("/etc/shadow", "r")
        for line in f:
            m = re.search(r'^root:(?P<salt>\$\d+\$[^\$]+\$)(?P<hash>[^:]+)', line)
            if m:
                calculated_hash = crypt.crypt("default", m.group('salt'))
                found_hash = f"{m.group('salt')}{m.group('hash')}"
                if calculated_hash != found_hash:
                    # root account doesn't use default password
                    controls['1.1.1'].setCorrectly = True
        f.close()

    def control_1_1_2(self):
        # 1.1.2 Ensure default password of admin is not used (Automated)
        try:
            p = subprocess.run('tmsh list auth user admin', shell=True, check=True, capture_output=True, encoding='utf-8')

        except:
            controls['1.1.2'].setCorrectly = True
            controls['1.1.2'].comment = 'Default user admin doesn\'t exist on this system.'
            return

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s{4}encrypted-password\s(?P<salt>\$\d+\$[^\$]+\$)(?P<hash>\S+)', line)
            if m:
                calculated_hash = crypt.crypt("admin", m.group('salt'))
                found_hash = f"{m.group('salt')}{m.group('hash')}"
                if calculated_hash != found_hash:
                    # admin account doesn't use default password
                    controls['1.1.2'].setCorrectly = True

    def control_1_1_3(self):
        # 1.1.3 Configure Secure Password Policy (Manual)
        p = subprocess.run('tmsh list auth password-policy all-properties', shell=True, check=True, capture_output=True, encoding='utf-8')

        requirements = { 'expiration-warning' : 14, 'lockout-duration': 300, 'max-duration' : 180, 'max-login-failures': 3,
                         'min-duration' : 90, 'minimum-length' : 12, 'password-memory' : 24, 'policy-enforcement' : 'enabled',
                         'required-lowercase' : 1, 'required-numeric' : 1, 'required-special' : 1, 'required-uppercase' : 1 }

        failed_requirements = {}

        for line in p.stdout.split("\n"):

            # expiration warning
            m = re.search(r'expiration-warning\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['expiration-warning']:
                    failed_requirements['expiration-warning'] = m.group('status')
                continue

            # lockout duration
            m = re.search(r'lockout-duration\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['lockout-duration']:
                    failed_requirements['lockout-duration'] = m.group('status')
                continue

            # max duration
            m = re.search(r'max-duration\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) > requirements['max-duration']:
                    failed_requirements['max-duration'] = m.group('status')
                continue

            # max login failures
            m = re.search(r'max-login-failures\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) == 0 or int(m.group('status')) > requirements['max-login-failures']:
                    failed_requirements['max-login-failures'] = m.group('status')
                continue

            # min duration
            m = re.search(r'min-duration\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['min-duration']:
                    failed_requirements['min-duration'] = m.group('status')
                continue

            # minimum length
            m = re.search(r'minimum-length\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['minimum-length']:
                    failed_requirements['minimum-length'] = m.group('status')
                continue

            # password memory
            m = re.search(r'password-memory\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['password-memory']:
                    failed_requirements['password-memory'] = m.group('status')
                continue

            # policy enforcement
            m = re.search(r'policy-enforcement\s(?P<status>\S+)', line)
            if m:
                if requirements['policy-enforcement'] != m.group('status'):
                    failed_requirements['policy-enforcement'] = m.group('status')
                continue

            # required lowercase
            m = re.search(r'required-lowercase\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['required-lowercase']:
                    failed_requirements['required-lowercase'] = m.group('status')
                continue

            # required numeric
            m = re.search(r'required-numeric\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['required-numeric']:
                    failed_requirements['required-numeric'] = m.group('status')
                continue

            # required special
            m = re.search(r'required-special\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['required-special']:
                    failed_requirements['required-special'] = m.group('status')
                continue

            # required uppercase
            m = re.search(r'required-uppercase\s(?P<status>\S+)', line)
            if m:
                if int(m.group('status')) < requirements['required-uppercase']:
                    failed_requirements['required-uppercase'] = m.group('status')
                continue

        if len(failed_requirements) > 0:
            controls['1.1.3'].setCorrectly = False
            failed_items = ""

            for failed_requirement in failed_requirements:
                failed_items += " " + failed_requirement

            controls['1.1.3'].comment = f'The following items didn\'t meet the requirements:{failed_items}.'
        else:
            controls['1.1.3'].setCorrectly = True

    def control_2_1(self):
        # 2.1 Ensure that Remote Radius is used for Authentication Only (Automated)
        p = subprocess.run('tmsh list auth source', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'type\sradius', line)
            if m:
                controls['2.1'].setCorrectly = True
                return

        controls['2.1'].setCorrectly = False
        controls['2.1'].comment = 'RADIUS isn\'t configured as authentication mechanism.'

    def control_2_2(self):
        # 2.2 Ensure redundant remote authentication servers are configured (Manual)
        p = subprocess.run('tmsh list auth radius-server', shell=True, check=True, capture_output=True, encoding='utf-8')

        radius_server_count = 0

        for line in p.stdout.split("\n"):
            m = re.search(r'auth\sradius-server\ssystem_auth_name', line)
            if m:
                radius_server_count += 1

        if radius_server_count == 2:
            controls['2.2'].setCorrectly = True
        else:
            controls['2.2'].setCorrectly = False
            controls['2.2'].comment = 'No redundant authentication servers configured.'

    def control_2_3(self):
        # 2.3 Ensure that "Fallback to local" option is disabled for Remote Authentication Settings (Manual)
        p = subprocess.run('tmsh list auth source all-properties', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'fallback\sfalse', line)
            if m:
                controls['2.3'].setCorrectly = True
                return

        controls['2.3'].setCorrectly = False
        controls['2.3'].comment = 'Option \'Fallback to local\' should be disabled.'

    def control_2_4(self):
        # 2.4 Ensure External Users' role is set to "No Access" (Automated)
        p = subprocess.run('tmsh list auth remote-user all-properties', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'default-role\sno-access', line)
            if m:
                controls['2.4'].setCorrectly = True
                return

        controls['2.4'].setCorrectly = False
        controls['2.4'].comment = 'External Users\' role should be set to \'No Access\'.'

    def control_2_5(self):
        # 2.5 Ensure External Users' has access to needed Partitions only (Automated)
        p = subprocess.run('tmsh list auth remote-user all-properties', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'default-partition\sall', line)
            if m:
                controls['2.5'].setCorrectly = False
                controls['2.5'].comment = 'Partition access for Exteral Users shouldn\'t be set to all.'
                return

        controls['2.5'].setCorrectly = True

    def control_2_6(self):
        # 2.6 Ensure External Users' Terminal Access is Disabled (Automated)
        p = subprocess.run('tmsh list auth remote-user all-properties', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'remote-console-access\sdisabled', line)
            if m:
                controls['2.6'].setCorrectly = True
                return

        controls['2.6'].setCorrectly = False
        controls['2.6'].comment = 'Terminal Access for External Users should be disabled.'

    def control_3_1(self):
        # 3.1 Ensure 'Idle timeout' is less than or equal to 10 minutes for Configuration utility sessions (Automated)
        p = subprocess.run('tmsh list sys httpd auth-pam-idle-timeout', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'auth-pam-idle-timeout\s(?P<timeout>\d+)', line)
            if m:
                if int(m.group('timeout')) > 0 and int(m.group('timeout')) <= 600:
                    controls['3.1'].setCorrectly = True
                    return

        controls['3.1'].setCorrectly = False
        controls['3.1'].comment = 'Idle timeout for GUI sessions should be enabled and less than or equal to 10 minutes.'

    # 3.2 Ensure access to Configuration utility by clients using TLS version 1.2 or later (Automated)
    def control_3_2(self):
        p = subprocess.run('tmsh list sys httpd ssl-protocol', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+ssl-protocol\sTLSv1.2$', line)
            if m:
                controls['3.2'].setCorrectly = True
                return

        controls['3.2'].setCorrectly = False
        controls['3.2'].comment = 'The configuration utility should be restricted to only allow TLS version 1.2.'


    # 3.3 Ensure access to Configuration utility is restricted to needed IP addresses only (Automated)
    def control_3_3(self):
        p = subprocess.run('tmsh list sys httpd allow', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+allow\s{\sAll', line)
            if m:
                controls['3.3'].setCorrectly = False
                controls['3.3'].comment = 'Access to the Configuration Utility should be restricted to a set of IP addresses.'
                return

        controls['3.3'].setCorrectly = True

    # 4.1 Ensure Prelogin 'Login Banner' is set (Manual)
    def control_4_1(self):
        banner_enabled = False
        banner_text = True

        p = subprocess.run('tmsh list sys sshd banner', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+banner\senabled$', line)
            if m:
                banner_enabled = True
                continue

        p = subprocess.run('tmsh list sys sshd banner-text', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+banner-text\snone$', line)
            if m:
                banner_text = False
                continue

        if banner_enabled == False:
            controls['4.1'].setCorrectly = False
            controls['4.1'].comment = 'Prelogin \'Login Banner\' for SSH should be enabled.'
            return

        if banner_text == False:
            controls['4.1'].setCorrectly = False
            controls['4.1'].comment = 'Prelogin \'Login Banner\' for SSH is missing.'
            return

        controls['4.1'].setCorrectly = True

    # 4.2 Ensure 'Idle timeout' is less than or equal to 10 minutes for SSH connections (Manual)
    def control_4_2(self):

        p = subprocess.run('tmsh list sys sshd inactivity-timeout', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+inactivity-timeout\s(?P<timeout>\d+)', line)
            if m:
                if int(m.group('timeout')) > 0 and int(m.group('timeout')) <= 600:
                    controls['4.2'].setCorrectly = True
                    return

        controls['4.2'].setCorrectly = False
        controls['4.2'].comment = 'Idle timeout for SSH connections should be enabled and less than or equal to 10 minutes.'

    # 4.3 Ensure 'Idle timeout' is less than or equal to 10 minutes for tmsh sessions (Manual)
    def control_4_3(self):

        p = subprocess.run('tmsh list cli global-settings idle-timeout', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+idle-timeout\s(?P<timeout>\d+)', line)
            if m:
                if int(m.group('timeout')) <= 10:
                    controls['4.3'].setCorrectly = True
                    return

        controls['4.3'].setCorrectly = False
        controls['4.3'].comment = 'Idle timeout for TMSH sessions should be enabled and less than or equal to 10 minutes.'

    # 4.4 Ensure 'Idle timeout' is less than or equal to 10 minutes for serial console sessions (Manual)
    def control_4_4(self):

        p = subprocess.run('tmsh list sys global-settings console-inactivity-timeout', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+console-inactivity-timeout\s(?P<timeout>\d+)', line)
            if m:
                if int(m.group('timeout')) > 0 and int(m.group('timeout')) <= 600:
                    controls['4.4'].setCorrectly = True
                    return

        controls['4.4'].setCorrectly = False
        controls['4.4'].comment = 'Idle timeout for serial console sessions should be enabled and less than or equal to 10 minutes.'

    # 4.5 Ensure minimum SSH Encryption algorithm is set to aes128 cbc (Manual)
    def control_4_5(self):

        p = subprocess.run('tmsh list /sys sshd include', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'Ciphers\saes128-cbc', line)
            if m:
                controls['4.5'].setCorrectly = True
                return

        controls['4.5'].setCorrectly = False
        controls['4.5'].comment = 'The minimum SSH Encryption algorithm should be set to aes128-cbc.'

    # 4.6 Ensure to set SSH MAC algorithm to hmac-sha2-256 (Manual)
    def control_4_6(self):

        p = subprocess.run('tmsh list /sys sshd include', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'MACs\shmac-sha2-256', line)
            if m:
                controls['4.6'].setCorrectly = True
                return

        controls['4.6'].setCorrectly = False
        controls['4.6'].comment = 'SSH MAC algorithm shoud be set to hmac-sha2-256.'

    # 4.7 Ensure to set Strong SSH KEY Exchange algorithm (Manual)
    def control_4_7(self):

        p = subprocess.run('tmsh list /sys sshd include', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'KexAlgorithms\sdiffie-hellman-group14-sha256', line)
            if m:
                controls['4.7'].setCorrectly = True
                return

        controls['4.7'].setCorrectly = False
        controls['4.7'].comment = 'Strong SSH Key Exchange algorithm should be set.'

    # 4.8 Ensure access SSH to CLI interface is restricted to needed IP addresses only (Manual)
    def control_4_8(self):

        p = subprocess.run('tmsh list sys sshd allow', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+allow\s{\sALL\s}$', line)
            if m:
                controls['4.8'].setCorrectly = False
                controls['4.8'].comment = 'Access SSH to CLI interface should be restricted to needed IP addresses only.'
                return

        controls['4.8'].setCorrectly = True

    # 5.1 Ensure redundant NTP servers are configured appropriately (Manual)
    def control_5_1(self):

        p = subprocess.run('tmsh list sys ntp servers', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+servers\s(?P<group_1>none|{(?P<group_2>[^}]+))', line)
            if m:
                if m.group('group_1') == "none":
                    controls['5.1'].setCorrectly = False
                    controls['5.1'].comment = 'NTP servers should be configured.'
                    return

                # check if configuration contains two or more NTP servers.
                n = re.search(r'^\s\S+\s\S+', m.group('group_2'))
                if n:
                    controls['5.1'].setCorrectly = True
                    return

        controls['5.1'].setCorrectly = False
        controls['5.1'].comment = 'Redundant NTP servers should be configured.'

    # 5.2 Ensure to exclude inode information from ETags HTTP Header (Manual)
    def control_5_2(self):
        p = subprocess.run('tmsh list sys httpd', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+include\s"FileETag\sMTime\sSize"$', line)
            if m:
                controls['5.2'].setCorrectly = True
                return

        controls['5.2'].setCorrectly = False
        controls['5.2'].comment = 'Inode information from ETags HTTP Header should be excluded.'

    # 5.3 Ensure port lockdown for self IP is set (Manual)
    def control_5_3(self):

        p = subprocess.run('tmsh -c \'cd /; list net self recursive all-properties\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        allow_service_started = False
        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+allow-service\sall', line)
            if m:
                controls['5.3'].setCorrecly = False
                controls['5.3'].comment = 'Port Lockdown on Self IP address shouldn\'t be set to \'Allow All\'.'
                return

            m = re.search(r'^\s+allow-service\s{', line)
            if m:
                allow_service_started = True
                continue

            m = re.search(r'^}$', line)
            if m and allow_service_started == True:
                allow_service_started = False
                continue

            m = re.search(r'^\s+default$', line)
            if m and allow_service_started == True:
                controls['5.3'].setCorrecly = False
                controls['5.3'].comment = 'Port Lockdown on Self IP address shouldn\'t be set to \'Allow Default\'.'
                return

        controls['5.3'].setCorrectly = True

    # 5.4 Ensure to disable unused services in BIG-IP configuration (Manual)
    def control_5_4(self):

        # check which modules are provisioned
        p = subprocess.run('tmsh -c \'list sys provision\'', shell=True, check=True, capture_output=True, encoding='utf-8')
        enabled_modules = []
        for line in p.stdout.split("\n"):
            m = re.search(r'^sys\sprovision\s(?P<module>\S+)\s{$', line)
            if m:
                enabled_modules.append(m.group('module'))
                continue

        # check for running services, that shouldn't be running given the provisioned modules
        p = subprocess.run('tmsh -c \'show sys service\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        services_that_should_be_disabled = []
        for line in p.stdout.split("\n"):
            m = re.search(r'^(?P<service>\S+)\s+run', line)
            if m:
                service = m.group('service')
                service_should_be_enabled = False
                for module in enabled_modules:
                    if module in enabled_services[service].modules:
                        service_should_be_enabled = True
                if service_should_be_enabled == False:
                    services_that_should_be_disabled.append(service)
                continue

        if len(services_that_should_be_disabled) > 0:
            controls['5.4'].setCorrectly = False
            controls['5.4'].comment = f'The following services possibly shouldn\'t be running: {services_that_should_be_disabled}'
        else:
            controls['5.4'].setCorrectly = True

    # 6.1 Ensure that SNMP access is allowed to trusted agents IPs only (Manual)
    def control_6_1(self):

        p = subprocess.run('tmsh -c \'list sys snmp allowed-addresses\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):

            m = re.search(r'^\s+allowed-addresses\snone$', line)
            if m:
                controls['6.1'].setCorrectly = True
                return

            m = re.search(r'^\s+allowed-addresses\s{(?P<data>[^}]+)}$', line)
            if m:
                data = m.group('data')
                for item in data.split(" "):
                    if len(item) > 0:
                        if item not in snmp_client_allow_list:
                            controls['6.1'].setCorrectly = False
                            controls['6.1'].comment = f'The IP address or network {item} isn\'t known as a trusted SNMP agent.'
                            return
                continue

        controls['6.1'].setCorrectly = True

    # 6.2 Ensure minimum SNMP version is set to V3 for agent access (Manual)
    def control_6_2(self):
        p = subprocess.run('tmsh -c \'list sys snmp all-properties\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):

            m = re.search(r'^\s+communities\snone$', line)
            if m:
                controls['6.2'].setCorrectly = True
                return

        controls['6.2'].setCorrectly = False
        controls['6.2'].comment = 'The SNMP configuration contains SNMPv1 and/or SNMPv2c communities.'

    # 6.3 Ensure to lockdown access logs to "Administrator , Resource Administrator and Auditor " roles only (Manual)
    def control_6_3(self):

        p = subprocess.run('tmsh -c \'list sys db ui.logaccess.*\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):

            m = re.search(r'^\s+value\s"enable"$', line)
            if m:
                controls['6.3'].setCorrectly = False
                controls['6.3'].comment = 'Log access should be limited to Administrator, Resource Administrator, Log Manager and Auditor.'
                return

        controls['6.3'].setCorrectly = True

    # 6.4 Ensure that audit logging for "MCP, tmsh and GUI" is set to enabled (Manual)
    def control_6_4(self):

        # check MCP
        p = subprocess.run('tmsh -c \'list sys db config.auditing\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+value\s"disable"$', line)
            if m:
                controls['6.4'].setCorrectly = False
                controls['6.4'].comment = 'Audit logging for MCP should be set to enabled.'
                return

        # check tmsh
        p = subprocess.run('tmsh -c \'list cli global-settings audit\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+audit\sdisabled$', line)
            if m:
                controls['6.4'].setCorrectly = False
                controls['6.4'].comment = 'Audit logging for tmsh should be set to enabled.'
                return

        # check GUI
        p = subprocess.run('tmsh -c \'list sys global-settings gui-audit\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+gui-audit\sdisabled$', line)
            if m:
                controls['6.4'].setCorrectly = False
                controls['6.4'].comment = 'Audit logging for GUI should be set to enabled.'
                return

        controls['6.4'].setCorrectly = True

    # 6.5 Ensure that Remote Syslog Servers are configured (Manual)
    def control_6_5(self):

        p = subprocess.run('tmsh -c \'list sys syslog remote-servers\'', shell=True, check=True, capture_output=True, encoding='utf-8')

        for line in p.stdout.split("\n"):
            m = re.search(r'^\s+remote-servers\snone$', line)
            if m:
                controls['6.5'].setCorrectly = False
                controls['6.5'].comment = 'At least one remote syslog server should be configured.'
                return

        controls['6.5'].setCorrectly = True


    # function to run controls
    def run_control(self, control: str):
        self.control = control
        do = f'control_{control.replace(".", "_")}'
        if hasattr(self, do) and callable(func := getattr(self, do)):
            func()

def set_controls():
    # 1 Accounts
    # 1.1 Passwords
    # 1.1.1 Ensure default password of root is not allowed (Automated)
    controls['1.1.1'] = CIS('1.1.1', 'Ensure default password of root is not allowed (Automated)')

    # 1.1.2 Ensure default password of admin is not used (Automated)
    controls['1.1.2'] = CIS('1.1.2', 'Ensure default password of admin is not used (Automated)')

    # 1.1.3 Configure Secure Password Policy (Manual)
    controls['1.1.3'] = CIS('1.1.3', 'Configure Secure Password Policy (Manual)')

    # 2 AAA
    # 2.1 Ensure that Remote Radius is used for Authentication Only (Automated)
    controls['2.1'] = CIS('2.1', 'Ensure that Remote Radius is used for Authentication Only (Automated)')

    # 2.2 Ensure redundant remote authentication servers are configured (Manual)
    controls['2.2'] = CIS('2.2', 'Ensure redundant remote authentication servers are configured (Manual)')

    # 2.3 Ensure that "Fallback to local" option is disabled for Remote Authentication Settings (Manual)
    controls['2.3'] = CIS('2.3', 'Ensure that "Fallback to local" option is disabled for Remote Authentication Settings (Manual)')

    # 2.4 Ensure External Users' role is set to "No Access" (Automated)
    controls['2.4'] = CIS('2.4', 'Ensure External Users\' role is set to "No Access" (Automated)')

    # 2.5 Ensure External Users' has access to needed Partitions only (Automated)
    controls['2.5'] = CIS('2.5', 'Ensure External Users\' has access to needed Partitions only (Automated)')

    # 2.6 Ensure External Users' Terminal Access is Disabled (Automated)
    controls['2.6'] = CIS('2.6', 'Ensure External Users\' Terminal Access is Disabled (Automated)')

    # 3 GUI Interface Management
    # 3.1 Ensure 'Idle timeout' is less than or equal to 10 minutes for Configuration utility sessions (Automated)
    controls['3.1'] = CIS('3.1', 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for Configuration utility sessions (Automated)')

    # 3.2 Ensure access to Configuration utility by clients using TLS version 1.2 or later (Automated)
    controls['3.2'] = CIS('3.2', 'Ensure access to Configuration utility by clients using TLS version 1.2 or later (Automated)')

    # 3.3 Ensure access to Configuration utility is restricted to needed IP addresses only (Automated)
    controls['3.3'] = CIS('3.3', 'Ensure access to Configuration utility is restricted to needed IP addresses only (Automated)')

    # 4 CLI Interface Management
    # 4.1 Ensure Prelogin 'Login Banner' is set (Manual)
    controls['4.1'] = CIS('4.1', 'Ensure Prelogin \'Login Banner\' is set (Manual)')

    # 4.2 Ensure 'Idle timeout' is less than or equal to 10 minutes for SSH connections (Manual)
    controls['4.2'] = CIS('4.2', 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for SSH connections (Manual)')

    # 4.3 Ensure 'Idle timeout' is less than or equal to 10 minutes for tmsh sessions (Manual)
    controls['4.3'] = CIS('4.3', 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for tmsh sessions (Manual)')

    # 4.4 Ensure 'Idle timeout' is less than or equal to 10 minutes for serial console sessions (Manual)
    controls['4.4'] = CIS('4.4', 'Ensure \'Idle timeout\' is less than or equal to 10 minutes for serial console sessions (Manual)')

    # 4.5 Ensure minimum SSH Encryption algorithm is set to aes128 cbc (Manual)
    controls['4.5'] = CIS('4.5', 'Ensure minimum SSH Encryption algorithm is set to aes128 cbc (Manual)')

    # 4.6 Ensure to set SSH MAC algorithm to hmac-sha2-256 (Manual)
    controls['4.6'] = CIS('4.6', 'Ensure to set SSH MAC algorithm to hmac-sha2-256 (Manual)')

    # 4.7 Ensure to set Strong SSH KEY Exchange algorithm (Manual)
    controls['4.7'] = CIS('4.7', 'Ensure to set Strong SSH KEY Exchange algorithm (Manual)')

    # 4.8 Ensure access SSH to CLI interface is restricted to needed IP addresses only (Manual)
    controls['4.8'] = CIS('4.8', 'Ensure access SSH to CLI interface is restricted to needed IP addresses only (Manual)')

    # 5 System
    # 5.1 Ensure redundant NTP servers are configured appropriately (Manual)
    controls['5.1'] = CIS('5.1', 'Ensure redundant NTP servers are configured appropriately (Manual)')

    # 5.2 Ensure to exclude inode information from ETags HTTP Header (Manual)
    controls['5.2'] = CIS('5.2', 'Ensure to exclude inode information from ETags HTTP Header (Manual)')

    # 5.3 Ensure port lockdown for self IP is set (Manual)
    controls['5.3'] = CIS('5.3', 'Ensure port lockdown for self IP is set (Manual)')

    # 5.4 Ensure to disable unused services in BIG-IP configuration (Manual)
    controls['5.4'] = CIS('5.4', 'Ensure to disable unused services in BIG-IP configuration (Manual)')

    # 6 Monitoring and Auditing
    # 6.1 Ensure that SNMP access is allowed to trusted agents IPs only (Manual)
    controls['6.1'] = CIS('6.1', 'Ensure that SNMP access is allowed to trusted agents IPs only (Manual)')

    # 6.2 Ensure minimum SNMP version is set to V3 for agent access (Manual)
    controls['6.2'] = CIS('6.2', 'Ensure minimum SNMP version is set to V3 for agent access (Manual)')

    # 6.3 Ensure to lockdown access logs to "Administrator , Resource Administrator and Auditor " roles only (Manual)
    controls['6.3'] = CIS('6.3', 'Ensure to lockdown access logs to "Administrator , Resource Administrator and Auditor " roles only (Manual)')

    # 6.4 Ensure that audit logging for "MCP, tmsh and GUI" is set to enabled (Manual)
    controls['6.4'] = CIS('6.4', 'Ensure that audit logging for "MCP, tmsh and GUI" is set to enabled (Manual)')

    # 6.5 Ensure that Remote Syslog Servers are configured (Manual)
    controls['6.5'] = CIS('6.5', 'Ensure that Remote Syslog Servers are configured (Manual)')

def set_enabled_services():

    # aced
    enabled_services['aced'] = EnabledServices('aced', 'Required for RSA SecureID authentication in APM.', 'enabled', ['apm'])

    # adfs_proxy
    enabled_services['adfs_proxy'] = EnabledServices('adfs_proxy', 'Required for ADFS proxy functionality in APM.', 'enabled', ['apm'])

    # admd
    enabled_services['admd'] = EnabledServices('admd', 'Required for stress-based DoS detection and mitigation control.', 'enabled', ['asm'])

    # alertd
    enabled_services['alertd'] = EnabledServices('alertd', 'Required for generating alerts.', 'enabled', ['ltm'])

    # apmd
    enabled_services['apmd'] = EnabledServices('apmd', 'Required for access policy enforcement in APM', 'enabled', ['apm'])

    # apm_websso
    enabled_services['apm_websso'] = EnabledServices('apm_websso', 'Required for the forward proxy chaining feature in APM', 'enabled', ['apm'])

    # antserver
    enabled_services['antserver'] = EnabledServices('antserver', 'Required for dynamic web content filtering for SWG in APM', 'enabled', ['apm'])

    # asmcrond
    enabled_services['asmcrond'] = EnabledServices('asmcrond', 'Required for executing tasks that are scheduled by asm_config_server.', 'enabled', ['asm'])

    # asmcsd
    enabled_services['asmcsd'] = EnabledServices('asmcsd', 'Required for triggering failover action if necessary.', 'enabled', ['asm'])

    # asmlogd
    enabled_services['asmlogd'] = EnabledServices('asmlogd', 'Required for storing request log data.', 'enabled', ['asm'])

    # asm_config_server
    enabled_services['asm_config_server'] = EnabledServices('asm_config_server', 'Required for access and modifications to the policy configuration.', 'enabled', ['asm'])

    # asm_config_rpc_handler
    enabled_services['asm_config_rpc_handler'] = EnabledServices('asm_config_rpc_handler', 'Required for access and modifications to the policy configuration.', 'enabled', ['asm'])

    # asm_start
    enabled_services['asm_start'] = EnabledServices('asm_start', 'Required for starting ASM daemons.', 'enabled', ['asm'])

    # autodiscd
    enabled_services['autodiscd'] = EnabledServices('autodiscd', 'Required for automatic discovery of services in AFM.', 'enabled', ['afm'])

    # autodosd
    enabled_services['autodosd'] = EnabledServices('autodosd', 'Required for threshold feature in AFM.', 'enabled', ['afm'])

    # avrd
    enabled_services['avrd'] = EnabledServices('avrd', 'Required for threshold feature in AFM.', 'enabled', ['ltm', 'avr', 'asm', 'afm'])

    # bcm56xxd
    enabled_services['bcm56xxd'] = EnabledServices('bcm56xxd', 'Required for switch daemon to configure and control Broadcom 56xx switch chips.', 'enabled', ['ltm'])

    # bd
    enabled_services['bd'] = EnabledServices('bd', 'Required for implementing ASM security policy.', 'enabled', ['asm'])

    # bdosd
    enabled_services['bdosd'] = EnabledServices('bdosd', 'Required for automatic generation of signatures in AFM.', 'enabled', ['afm'])

    # bd_agent
    enabled_services['bd_agent'] = EnabledServices('bd_agent', 'Required for sending policy configuration to the bd process.', 'enabled', ['asm'])

    # bigd
    enabled_services['bigd'] = EnabledServices('bigd', 'Required for monitoring.', 'enabled', ['ltm'])

    # big3d
    enabled_services['big3d'] = EnabledServices('big3d', 'Required for monitoring GTM.', 'enabled', ['gtm', 'ltm'])

    # botd
    enabled_services['botd'] = EnabledServices('botd', 'Required for correlating bot detection data.', 'enabled', ['asm'])

    # bwafconfd
    enabled_services['bwafconfd'] = EnabledServices('bwafconfd', 'Required for tracking configuration from the cortex portal.', 'enabled', ['ltm'])

    # cand
    enabled_services['cand'] = EnabledServices('cand', 'Required for communication among cards in VIPRION.', 'enabled', ['ltm'])

    # captured
    enabled_services['captured'] = EnabledServices('captured', 'Required for automatic packet capture in ASM.', 'enabled', ['asm'])

    # cbrd
    enabled_services['cbrd'] = EnabledServices('cbrd', 'Required for XML profile used in virtual servers.', 'enabled', ['ltm'])

    # chmand
    enabled_services['chmand'] = EnabledServices('chmand', 'Required for publish platform info to MCPD.', 'enabled', ['ltm'])

    # clean_db
    enabled_services['clean_db'] = EnabledServices('clean_db', 'Required for monitoring ASM database tables and delete old records', 'enabled', ['asm'])

    # clusterd
    enabled_services['clusterd'] = EnabledServices('clusterd', 'Required for manage blade clustering for VIPRION systems.', 'enabled', ['ltm'])

    # correlation
    enabled_services['correlation'] = EnabledServices('correlation', 'Required for Event Correlation page in ASM (11.1.0-13.x.x).', 'enabled', ['asm'])

    # crond
    enabled_services['crond'] = EnabledServices('crond', 'Required for running scheduled commands.', 'enabled', ['ltm'])

    # csyncd
    enabled_services['csyncd'] = EnabledServices('csyncd', 'Required for populating the software image table.', 'enabled', ['ltm'])

    # datasyncd
    enabled_services['datasyncd'] = EnabledServices('datasyncd', 'Required for features like Proactive Bot Defense, CATPCHA and JavaScript challenges.', 'enabled', ['asm'])

    # DBDaemon
    enabled_services['DBDaemon'] = EnabledServices('DBDaemon', 'Required for SQL monitoring.', 'enabled', ['ltm'])

    # dcc
    enabled_services['dcc'] = EnabledServices('dcc', 'Required for policy updates (removed in 11.6.0).', 'enabled', ['asm'])

    # devmgmtd
    enabled_services['devmgmtd'] = EnabledServices('devmgmtd', 'Required for trust group functionality.', 'enabled', ['ltm'])

    # diskevent
    enabled_services['diskevent'] = EnabledServices('diskevent', 'Required for monitoring or logging of major disk errors.', 'enabled', ['ltm'])

    # dnscached
    enabled_services['dnscached'] = EnabledServices('dnscached', 'Required for DNS cache functionality in APM.', 'enabled', ['apm'])

    # dosl7d
    enabled_services['dosl7d'] = EnabledServices('dosl7d', 'Required for L7 DoS protection.', 'enabled', ['asm'])

    # dwbld
    enabled_services['dwbld'] = EnabledServices('dwbld', 'Required for AFM IP intelligence feature.', 'enabled', ['afm'])

    # dynconfd
    enabled_services['dynconfd'] = EnabledServices('dynconfd', 'Required for commmunication with DNS servers.', 'enabled', ['ltm'])

    # eam
    enabled_services['eam'] = EnabledServices('eam', 'Required for third-party identity integration in APM.', 'enabled', ['apm'])

    # eca
    enabled_services['eca'] = EnabledServices('eca', 'Required for NTLM authentication in APM.', 'enabled', ['apm'])

    # errdefsd
    enabled_services['errdefsd'] = EnabledServices('errdefsd', 'Required for high-speed logging via mgmt interface.', 'enabled', ['ltm'])

    # eventd
    enabled_services['eventd'] = EnabledServices('eventd', 'Required for iControl-based subscription messaging.', 'enabled', ['ltm'])

    # evrouted
    enabled_services['evrouted'] = EnabledServices('evrouted', 'Required for handling all events on the local control plane.', 'enabled', ['ltm'])

    # fpdd
    enabled_services['fpdd'] = EnabledServices('fpdd', 'Required for drawing screens on the LCD panel and LED management.', 'enabled', ['ltm'])

    # fslogd
    enabled_services['fslogd'] = EnabledServices('fslogd', 'Required for local logging and reporting in APM.', 'enabled', ['apm', 'afm'])

    # gtmd
    enabled_services['gtmd'] = EnabledServices('gtmd', 'Required for global traffic functionality.', 'enabled', ['gtm'])

    # guestagentd
    enabled_services['guestagentd'] = EnabledServices('guestagentd', 'Required for vCMP guest communication with vCMP host.', 'enabled', ['ltm'])

    # hostagentd
    enabled_services['hostagentd'] = EnabledServices('hostagentd', 'Required for vCMP guest communication with vCMP host.', 'enabled', ['ltm'])

    # htconnector
    enabled_services['htconnector'] = EnabledServices('htconnector', 'Required.', 'enabled', ['ltm'])

    # httpd
    enabled_services['httpd'] = EnabledServices('httpd', 'Required for BIG-IP Configuration Utility.', 'enabled', ['ltm'])

    # httpd_apm
    enabled_services['httpd_apm'] = EnabledServices('httpd_apm', 'Required for rendering end-user pages in APM.', 'enabled', ['apm'])

    # httpd_sam
    enabled_services['httpd_sam'] = EnabledServices('httpd_sam', 'Required for generating user-facting HTML pages in APM.', 'enabled', ['apm'])

    # hwpd
    enabled_services['hwpd'] = EnabledServices('hwpd', 'Required for ePVA and DNS hardware acceleration.', 'enabled', ['ltm'])

    # icrd_child
    enabled_services['icrd_child'] = EnabledServices('icrd_child', 'Required for command access for iControl using REST.', 'enabled', ['ltm'])

    # icr_eventd
    enabled_services['icr_eventd'] = EnabledServices('icr_eventd', 'Required for monitoring any changes to configuration objects and publishing the change event.', 'enabled', ['ltm'])

    # iprepd
    enabled_services['iprepd'] = EnabledServices('iprepd', 'Required for IP reputation database update.', 'enabled', ['ltm', 'afm', 'asm'])

    # keymgmtd
    enabled_services['keymgmtd'] = EnabledServices('keymgmtd', 'Required for CA-bundle management.', 'enabled', ['ltm'])

    # lacpd
    enabled_services['lacpd'] = EnabledServices('lacpd', 'Required for link aggregation functionality.', 'enabled', ['ltm'])

    # learning_manager
    enabled_services['learning_manager'] = EnabledServices('learning_manager', 'Required for creating learning suggestions.', 'enabled', ['asm'])

    # lind
    enabled_services['lind'] = EnabledServices('lind', 'Required for software installation functionality.', 'enabled', ['ltm'])

    # lldpd
    enabled_services['lldpd'] = EnabledServices('lldpd', 'Required for the Link Layer Discovery Protocol daemon.', 'enabled', ['ltm'])

    # localdbmgr
    enabled_services['localdbmgr'] = EnabledServices('localdbmgr', 'Required for entries in LocalDB in APM.', 'enabled', ['apm'])

    # logmysqld
    enabled_services['logmysqld'] = EnabledServices('logmysqld', 'Required for loading log data into mysql in APM.', 'enabled', ['apm', 'afm'])

    # logstatd
    enabled_services['logstatd'] = EnabledServices('logstatd', 'Required for parsing log data for utilities.', 'enabled', ['ltm'])

    # log_manager
    enabled_services['log_manager'] = EnabledServices('log_manager', 'Required for running ASM-specific log file tasks.', 'enabled', ['asm'])

    # lopd
    enabled_services['lopd'] = EnabledServices('lopd', 'Required for lights-out processor subsystem.', 'enabled', ['ltm'])

    # mcpd
    enabled_services['mcpd'] = EnabledServices('mcpd', 'Required for traffic management functionality.', 'enabled', ['ltm'])

    # merged
    enabled_services['merged'] = EnabledServices('merged', 'Required for statistical data for system utilities and graphs.', 'enabled', ['ltm'])

    # mgmt_acld
    enabled_services['mgmt_acld'] = EnabledServices('mgmt_acld', 'Required for maintaining statistics and logging of Management Port AFM rules.', 'enabled', ['ltm', 'afm'])

    # monpd
    enabled_services['monpd'] = EnabledServices('monpd', 'Required for creating reporting charts.', 'enabled', ['ltm', 'avr', 'apm', 'asm', 'afm'])

    # mdmsyncmgr
    enabled_services['mdmsyncmgr'] = EnabledServices('mdmsyncmgr', 'Required to store MDM-managed endpoint list in local MySQL database in APM.', 'enabled', ['apm'])

    # mysql
    enabled_services['mysql'] = EnabledServices('mysql', 'Required to store data in local MySQL database in APM.', 'enabled', ['apm', 'asm', 'afm'])

    # mysqlhad
    enabled_services['mysqlhad'] = EnabledServices('mysqlhad', 'Required to monitor the mysqld process.', 'enabled', ['asm'])

    # named
    enabled_services['named'] = EnabledServices('named', 'Required for BIND functionality.', 'enabled', ['ltm'])

    # neurond
    enabled_services['neurond'] = EnabledServices('neurond', 'Required for interaction with Neuron Network Search Processor chip.', 'enabled', ['ltm'])

    # nlad
    enabled_services['nlad'] = EnabledServices('nlad', 'Required for NTLM authentication in APM.', 'enabled', ['apm'])

    # nslcd
    enabled_services['nslcd'] = EnabledServices('nslcd', 'Required for LDAP authentication.', 'enabled', ['ltm'])

    # nsyncd
    enabled_services['nsyncd'] = EnabledServices('nsyncd', 'Required for LiveUpdate resources.', 'enabled', ['asm'])

    # ntlmconnpool
    enabled_services['ntlmconnpool'] = EnabledServices('ntlmconnpool', 'Required for NTLM connection pooling.', 'enabled', ['ltm'])

    # ntpd
    enabled_services['ntpd'] = EnabledServices('ntpd', 'Required for correct system time.', 'enabled', ['ltm'])

    # nwd
    enabled_services['nwd'] = EnabledServices('nwd', 'Required for monitoring ASM daemons and restarting them if needed.', 'enabled', ['asm'])

    # oauth
    enabled_services['oauth'] = EnabledServices('oauth', 'Required for OAuth authentication in APM.', 'enabled', ['apm'])

    # omapd
    enabled_services['omapd'] = EnabledServices('omapd', 'Required for user identification for SWG in APM.', 'enabled', ['apm'])

    # overdog
    enabled_services['overdog'] = EnabledServices('overdog', 'Required for HA failover actions.', 'enabled', ['ltm'])

    # ovsdb-server
    enabled_services['ovsdb-server'] = EnabledServices('ovsdb-server', 'Required for management via OVSDB protocol.', 'enabled', ['ltm'])

    # pabnagd
    enabled_services['pabnagd'] = EnabledServices('pabnagd', 'Required for automated policy building operations.', 'enabled', ['asm'])

    # pccd
    enabled_services['pccd'] = EnabledServices('pccd', 'Required for detecting and compiling firewall configuation changes.', 'enabled', ['ltm', 'afm'])

    # ping_access_agent
    enabled_services['ping_access_agent'] = EnabledServices('ping_access_agent', 'Required for Ping Identity in APM.', 'enabled', ['apm'])

    # pfmand
    enabled_services['pfmand'] = EnabledServices('pfmand', 'Required for link monitoring, link statistics, and media settings.', 'enabled', ['ltm'])

    # pgadmind
    enabled_services['pgadmind'] = EnabledServices('pgadmin', 'Required for starting PostgreSQL server and monitoring.', 'enabled', ['afm'])

    # pkcs11d
    enabled_services['pkcs11d'] = EnabledServices('pkcs11d', 'Required for communication with third-party network connected HSMs.', 'enabled', ['ltm'])

    # platform_agent
    enabled_services['platform_agent'] = EnabledServices('platform_agent', 'Required for tenants running on Velos or rSeries hardware.', 'enabled', ['ltm'])

    # racoon
    enabled_services['racoon'] = EnabledServices('racoon', 'Required for running IPsec tunnels.', 'enabled', ['ltm'])

    # rba
    enabled_services['rba'] = EnabledServices('rba', 'Required for client-side Kerberos authentication in APM.', 'enabled', ['apm'])

    # recovery_manager
    enabled_services['recovery_manager'] = EnabledServices('recovery_manager', 'Required for starting ASM daemons (removed in 11.6.0).', 'enabled', ['asm'])

    # resourcemgr
    enabled_services['resourcemgr'] = EnabledServices('resourcemgr', 'Required for the Trusted Platform Module (TPM).', 'enabled', ['ltm'])

    # rewrite
    enabled_services['rewrite'] = EnabledServices('rewrite', 'Required for rewriting Portal Access web links in APM.', 'enabled', ['apm'])

    # restjavad
    enabled_services['restjavad'] = EnabledServices('restjavad', 'Required for control-plane access using HTTP REST API and OAuth/AGC in APM.', 'enabled', ['ltm', 'apm'])

    # restnoded
    enabled_services['restnoded'] = EnabledServices('restnoded', 'Required for control-plane access using HTTP REST API and OAuth/AGC in APM.', 'enabled', ['ltm', 'apm'])

    # rmonsnmpd
    enabled_services['rmonsnmpd'] = EnabledServices('rmonsnmpd', 'Required for SNMP functionality.', 'enabled', ['ltm'])

    # samlidpd
    enabled_services['samlidpd'] = EnabledServices('samlidpd', 'Required for creation of SAML IdP connector in APM.', 'enabled', ['apm'])

    # scriptd
    enabled_services['scriptd'] = EnabledServices('scriptd', 'Required for running application implementation scripts.', 'enabled', ['ltm'])

    # sdmd
    enabled_services['sdmd'] = EnabledServices('sdmd', 'Required for spawning the node.js engines in the iRuleLX framework.', 'enabled', ['ilx'])

    # sflow_agent
    enabled_services['sflow_agent'] = EnabledServices('sflow_agent', 'Required for sflow data to be accessible via SNMP.', 'enabled', ['ltm'])

    # snmpd
    enabled_services['snmpd'] = EnabledServices('snmpd', 'Required for SNMP functionality.', 'enabled', ['ltm'])

    # sod
    enabled_services['sod'] = EnabledServices('sod', 'Required for HA failover capability.', 'enabled', ['ltm'])

    # sshd
    enabled_services['sshd'] = EnabledServices('sshd', 'Required for SSH command line access.', 'enabled', ['ltm'])

    # sshplugin
    enabled_services['sshplugin'] = EnabledServices('sshplugin', 'Required to perform protocol-specific limitations on SSH.', 'enabled', ['afm'])

    # statsd
    enabled_services['statsd'] = EnabledServices('statsd', 'Required for collecting statistics and record them in the rrd files.', 'enabled', ['ltm'])

    # stpd
    enabled_services['stpd'] = EnabledServices('stpd', 'Required for bridge-loop detection using Spanning Tree Protocol (STP).', 'enabled', ['ltm'])

    # syscalld
    enabled_services['syscalld'] = EnabledServices('syscalld', 'Required for system call functions.', 'enabled', ['ltm'])

    # syslog-ng
    enabled_services['syslog-ng'] = EnabledServices('syslog-ng', 'Required for system logging.', 'enabled', ['ltm'])

    # tamd
    enabled_services['tamd'] = EnabledServices('tamd', 'Required for authorizing traffic.', 'enabled', ['ltm'])

    # tamd
    enabled_services['tasd'] = EnabledServices('tasd', 'Required.', 'enabled', ['ltm'])

    # tmipsecd
    enabled_services['tmipsecd'] = EnabledServices('tmipsecd', 'Required for notification from IPsec-related configuration objects.', 'enabled', ['ltm'])

    # tmm
    enabled_services['tmm'] = EnabledServices('tmm', 'Required for traffic management functionality.', 'enabled', ['ltm'])

    # tmrouted
    enabled_services['tmrouted'] = EnabledServices('tmrouted', 'Required for updating the TMM routing table.', 'enabled', ['ltm'])

    # tomcat
    enabled_services['tomcat'] = EnabledServices('tomcat', 'Required for web utility in APM.', 'enabled', ['ltm', 'apm'])

    # tsconfigd
    enabled_services['tsconfigd'] = EnabledServices('tsconfigd', 'Required for forwaring policy updates to bd.', 'enabled', ['asm'])

    # updated
    enabled_services['updated'] = EnabledServices('updated', 'Required.', 'enabled', ['ltm'])

    # urldb
    enabled_services['urldb'] = EnabledServices('urldb', 'Required for SWG URL categorization in SWG.', 'enabled', ['urldb', 'swg'])

    # urldbmgrd
    enabled_services['urldbmgrd'] = EnabledServices('urldbmgrd', 'Required for SWG URL categorization in SWG.', 'enabled', ['urldb', 'swg'])

    # vcmpd
    enabled_services['vcmpd'] = EnabledServices('vcmpd', 'Required for managing and running vCMP guests.', 'enabled', ['ltm'])

    # vdi
    enabled_services['vdi'] = EnabledServices('vdi', 'Required for Citrix and RDP in APM.', 'enabled', ['apm'])

    # verify_dcc
    enabled_services['verify_dcc'] = EnabledServices('verify_dcc', 'Required for monitoring dcc daemon.', 'enabled', ['asm'])

    # vxland
    enabled_services['vxland'] = EnabledServices('vxland', 'Required for VXLAN traffic.', 'enabled', ['ltm'])

    # wccpd
    enabled_services['wccpd'] = EnabledServices('wccpd', 'Required Web Cache Communication Protocol in AAM.', 'enabled', ['aam', 'ltm', 'apm', 'afm', 'asm', 'pem'])

    # webssh
    enabled_services['webssh'] = EnabledServices('webssh', 'Required.', 'enabled', ['apm'])

    # websso
    enabled_services['websso'] = EnabledServices('websso', 'Required for SSO in APM.', 'enabled', ['apm'])

    # zrd
    enabled_services['zrd'] = EnabledServices('zrd', 'Required for running ZoneRunner which is required for GTM.', 'enabled', ['gtm'])

    # zxfrd
    enabled_services['zxfrd'] = EnabledServices('zxfrd', 'Required managing zone transfers.', 'enabled', ['ltm'])

def get_system_information():

    global software_build
    global software_edition
    global software_version

    p = subprocess.run('tmsh show sys version', shell=True, check=True, capture_output=True, encoding='utf-8')

    for line in p.stdout.split("\n"):
        m = re.search(r'Version\s+(?P<version>\S+)', line)
        if m:
            software_version = m.group('version')
            continue

        m = re.search(r'Build\s+(?P<build>\S+)', line)
        if m:
            software_build = m.group('build')
            continue

        m = re.search(r'Edition\s+(?P<edition>.*)', line)
        if m:
            software_edition = m.group('edition')
            continue

def check_controls():
    r = ControlFunctions()
    for control in controls:
        r.run_control(controls[control].control)

def set_exceptions():
    for control in controls:
        if exceptions.get(control):
            controls[control].setException = True
            controls[control].exceptionText = exceptions[control]

def report_to_stdout():
    for control in controls:
        print(f"[{control}] {controls[control].description}")
        print(f"......Set Correctly: {controls[control].setCorrectly}")
        print(f"......Comment: {controls[control].comment}")
        print(f"......Set Exception: {controls[control].setException}")
        print(f"......Exception Text: {controls[control].exceptionText}\n")

def generate_html():

    html = "<html><head>"
    html += generate_css()
    html += "</head><body>"
    html += generate_html_report()
    html += "</body></html>"

    return html


def report_by_email():
    message = MIMEMultipart("alternative")
    message["Subject"] = f"CIS F5 Benchmark Report | {hostname} | Score {benchmark_totals['correct_percentage']}%"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = "This e-mail requires a HTML capable e-mail client."

    html = generate_html()

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")
    message.attach(part1)
    message.attach(part2)

    context=ssl.create_default_context()

    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.ehlo(name='ipforward.synology.me')
        server.login(login, password)
        server.sendmail(
            sender_email, receiver_email, message.as_string()
        )

def report_to_file(output_file):
    f = open(output_file, "w")
    f.write(generate_html())
    f.close()

def calculate_benchmark_totals():

    count_correct = 0
    count_incorrect = 0
    count_exceptions = 0

    for control in controls:
        if controls[control].setCorrectly == True:
            count_correct += 1
            continue
        if controls[control].setException == True:
            count_exceptions += 1
            continue
        count_incorrect += 1

    benchmark_totals['correct'] = count_correct
    benchmark_totals['incorrect'] = count_incorrect
    benchmark_totals['exceptions'] = count_exceptions

    benchmark_totals['correct_percentage'] = int(round(((100 * count_correct) / len(controls)), 0))
    benchmark_totals['incorrect_percentage'] = int(round(((100 * count_incorrect) / len(controls)), 0))
    benchmark_totals['exceptions_percentage'] = int(round(((100 * count_exceptions) / len(controls)), 0))

def generate_css():
    css = (
        '* { font-family: \'Trebuchet MS\', \'Lucida Sans Unicode\', \'Lucida Grande\', \'Lucida Sans\', Arial, sans-serif; -webkit-box-sizing: border-box; -moz-box-sizing: border-box; box-sizing: border-box; }\n'
        'p { margin-top: 2px; margin-bottom: 0px; display: block; }\n'
        'span { display: block; }\n'
        '.rule { margin-bottom: 5px; }\n'
        '.control { vertical-align: top; width: 400px; background-color: rgb(240, 240, 240); margin: 1px; padding-top: 0px; padding-left: 5px; padding-right: 5px; border-top: 1px solid white; border-right: 1px solid white; }\n'
        '.set-correct { vertical-align: top; width: 100px; background-color: rgb(240, 240, 240); margin: 1px; padding-top: 0px; padding-left: 5px; border-top: 1px solid white; border-right: 1px solid white; }\n'
        '.comment { vertical-align: top; width: 300px; background-color: rgb(240, 240, 240); margin: 1px; padding-top: 0px; padding-left: 5px; padding-right: 5px; border-top: 1px solid white; }\n'
        '.invalid { color: red; font-size: 30px; text-align: center; text-shadow: 2px 2px lightgray; }\n'
        '.valid { color: green; font-size: 30px; font-weight: bold; text-align: center; text-shadow: 2px 2px lightgray; }\n'
        '.invalid-exception { color: orange; font-size: 30px; font-weight: bold; text-align: center; text-shadow: 2px 2px lightgray; }\n'
        '.header-title { text-align: center; font-size: 20px; font-weight: bold; }\n'
        '.title1 { margin-top: 5px; font-size: 15px; font-weight: bold; font-variant: small-caps; color: darkslategrey; }\n'
        '.footer { width: 800px; background-color: rgb(240, 240, 240); margin-top: 1px; }\n'
        '.footer p { margin-top: 3px; margin-right: 5px; margin-bottom: 0px; line-height: 0.8; }\n'
        '.footer p span { font-size: 10px; display: block; }\n'
        '.footer span { float: right; }\n'
    )

    html = "<style>\n"
    html += css
    html += "</style>\n"

    return html

def generate_html_report():

    date_today = datetime.datetime.now().strftime("%B %d, %Y")
    score = benchmark_totals['correct_percentage']

    html = '<body>\n'

    html += '<table cellspacing="0" cellpadding="0" style="border-spacing: 0px; margin-left: 2px;">\n'
    html += '<tr style="background-color: #eee;"><td colspan="4" style="background-color: #eee; width:803px; text-align: center;">\n'
    html += '<p><span class="header-title">CIS F5 Benchmark Report</span></p>\n'
    html += '</td></tr>\n'

    html += '<tr style="background-color: #eee;"><td rowspan="4" style="background-color: #eee; width: 120px; vertical-align: top; padding-left: 10px;">\n'
    html += f'<img src="https://ipforward.nl/cis/piechart.php?c={benchmark_totals["correct_percentage"]}&e={benchmark_totals["exceptions_percentage"]}&i={benchmark_totals["incorrect_percentage"]}" />'
    html += '</td>'
    html += '<td colspan="3" style="background-color: #eee; width: 280px; vertical-align: bottom;">\n'
    html += '<p><span class="title1">host</span></p>\n'
    html += '</td></tr>\n'

    html += '<tr><td colspan="3" style="background-color: #eee; width: 280px; vertical-align: bottom; padding-bottom: 10px;">\n'
    html += f'<p><span>{hostname}</span></p>\n'
    html += '</td></tr>\n'

    html += '<tr><td style="background-color: #eee; width: 280px; vertical-align: bottom;">\n'
    html += '<p><span class="title1">software version</span></p>\n'
    html += '</td><td colspan="2" style="background-color: #eee; vertical-align: bottom;">\n'
    html += '<p style="margin-left: 5px;"><span class="title1">date</span></p>\n'
    html += '</td></tr>\n'

    html += '<tr><td style="background-color: #eee; width: 280px; vertical-align: top; padding-bottom: 10px;">\n'
    html += f'<p><span>{software_version} Build {software_build} {software_edition}</span></p>\n'
    html += '</td><td colspan="2" style="background-color: #eee; width: 280px; vertical-align: top; padding-bottom: 10px;">\n'
    html += f'<p style="margin-left: 5px;"><span>{date_today}</span></p>\n'
    html += '</td></tr>\n'

    for control in controls:
        html += '<tr>\n'
        html += f'<td colspan="2" class="control"><p><span class="title1">control {control}</span></p></td>\n'

        if controls[control].setCorrectly == True:
            html += f'<td class="set-correct"><p class="rule"><span class="title1">set&nbsp;correctly</span></p></td>'
            html += f'<td class="comment"><p class="rule"><span class="title1">comment</span></p></td>'
        elif controls[control].setException == True:
            html += f'<td class="set-correct"><p class="rule"><span class="title1">set&nbsp;correctly</span></p></td>'
            html += f'<td class="comment"><p class="rule"><span class="title1">exception</span></p></td>'
        else:
            html += f'<td class="set-correct"><p class="rule"><span class="title1">set&nbsp;correctly</span></p></td>'
            html += f'<td class="comment"><p class="rule"><span class="title1">comment</span></p></td>'

        html += '</tr><tr>'
        html += f'<td colspan="2" class="control"><p class="rule"><span>{controls[control].description}</span></p></td>\n'

        if controls[control].setCorrectly == True:
            html += f'<td class="set-correct"><p class="rule"></span><span class="valid">&#10003;</span></p></td>\n'
            html += f'<td class="comment"><p class="rule"><span></span></p></td>\n'
        elif controls[control].setException == True:
            html += f'<td class="set-correct"><p class="rule"><span class="invalid-exception">&#10003;</span></p></td>\n'
            html += f'<td class="comment"><p class="rule"><span>{controls[control].exceptionText}</span></p></td>\n'
        else:
            html += f'<td class="set-correct"><p class="rule"><span class="invalid">&#10008;</span></p></td>\n'
            html += f'<td class="comment"><p class="rule"><span>{controls[control].comment}</span></p></td>\n'

        html += '</tr>\n'

    html += '<tr style="background-color: #eee;"><td colspan="4" style="padding-right: 5px; text-align: right; background-color: #eee; border-top: 1px solid #fff;">\n'
    html += f'<p><span style="font-size: 10px;">CIS F5 Benchmark Reporter {version}</span></p>\n'
    html += '</td></tr>\n'
    html += '<tr><td colspan="4" style="padding-right: 5px; text-align: right; background-color: #eee; border-top: 0px;">\n'
    html += '<p><span style="font-size: 10px;">by Niels van Sluis</span></p>\n'
    html += '</td><tr>\n'
    html += '</table>'

    return html

def print_help():
    print('Usage: CIS_F5_Benchmark_Reporter.py [OPTION]...\n')
    print('Mandatory arguments to long options are mandatory for short options too.')
    print('  -f, --file=FILE            output report to file.')
    print('  -m, --mail                 output report to mail.')
    print('  -s, --screen               output report to screen.')
    print('\nReport bugs to nvansluis@gmail.com')

def main():

    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'f:ms', ['file =','mail','screen'])
    except getopt.error as err:
        print_help()
        sys.exit(2)

    output = None
    output_file = None

    for opt, arg in options:
        if opt in ('-f', '--file'):
            output='file'
            output_file = arg
        elif opt in ('-s', '--screen'):
            output='screen'
        elif opt in ('-m', '--mail'):
            output='mail'

    if output == None:
        print_help()
        sys.exit()

    # initialize controls
    set_controls()

    # initialze enabled services
    set_enabled_services()

    # retrieve system information
    get_system_information()

    # check controls
    check_controls()

    # apply exceptions
    set_exceptions()

    # calculate benchmark totals
    calculate_benchmark_totals()

    if output == "file":
        # report output to file
        print(f'output to file: {arg}')
        report_to_file(arg)
    elif output == "screen":
        # report outcome to screen
        report_to_stdout()
    elif output == "mail":
        # send report via e-mail
        report_by_email()

if __name__ == "__main__":
    main()
