# Gufw - https://costales.github.io/projects/gufw/
# Copyright (C) 2008-2020 Marcos Alvarez Costales https://costales.github.io
#
# Gufw is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Gufw is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Gufw; if not, see http://www.gnu.org/licenses for more
# information.

from os import listdir
from re import findall, search
from socket import AF_INET, SOCK_DGRAM, socket
from subprocess import PIPE, Popen

POL_IN     = 'incoming'
POL_OUT    = 'outgoing'
POL_ROUTED = 'routed'

class Firewall():
    UFW_PATH    = '/usr/sbin/ufw'
    UFW_DEFAULT = '/etc/default/ufw'
    UFW_CONF    = '/etc/ufw/ufw.conf'

    _POL_DIR = {
        POL_IN:     'INPUT',
        POL_OUT:    'OUTPUT',
        POL_ROUTED: 'FORWARD'
    }

    _POL_ALIAS = {
        'ACCEPT': 'allow',
        'DROP':   'deny',
        'REJECT': 'reject'
    }
    
    def __init__(self):
        pass
    
    def _run_cmd(self, cmd, lang_c=False):
        if lang_c:
            proc = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE, env={'LANG':'C'})
        else:
            proc = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
        stdout,stderr=proc.communicate()
        
        if stderr and not stderr.decode().startswith("WARN") and not stderr.decode().startswith("DEBUG"): # Error
            return stderr.decode('utf-8')
        else: # OK
            return stdout.decode('utf-8')
    
    def read_default(self, split_lines=False):
        with open(self.UFW_DEFAULT) as f:
            return f.readlines() if split_lines else f.read()

    def read_conf(self, split_lines=False):
        with open(self.UFW_CONF) as f:
            return f.readlines() if split_lines else f.read()

    def get_status(self):
        return ('Status: active' in self._run_cmd([self.UFW_PATH, 'status'], True))
    
    def set_status(self, status:bool):
        self._run_cmd([self.UFW_PATH, '--force', 'enable' if status else 'disable'])
    
    def get_version(self):
        return search(r'ufw ([\d.]+)', self._run_cmd([self.UFW_PATH, 'version'])).group(1)

    def get_policy(self, policy:str) -> str:
        if policy == POL_ROUTED and search(r'=\s*(\d+)', self._run_cmd(['sysctl', 'net.ipv4.ip_forward'])).group(1) == '0':
            return 'disabled'
        
        return self._POL_ALIAS[search(
            'DEFAULT_' + self._POL_DIR[policy] + r'_POLICY\s*=\s*(["\'`]*)(\w*)\1',
            self.read_default()).group(2)]
    
    def set_policy(self, value:str, policy:str):
        if value.lower() in ['incoming', 'outgoing', 'routed'] and policy.lower() in ['allow', 'deny', 'reject']:
            self._run_cmd([self.UFW_PATH, 'default', policy, value])
    
    def get_ufw_logging(self):
        try:
            return search(r'LOGLEVEL\s*=\s*(["\'`]*)(\w*)\1', self.read_conf()).group(2)
        except AttributeError:
            return 'off'
    
    def set_ufw_logging(self, logging:str):
        if logging.lower() in ['off', 'low', 'medium', 'high', 'full']:
            self._run_cmd([self.UFW_PATH, 'logging', logging])
    
    def reset_fw(self):
        self._run_cmd([self.UFW_PATH, '--force', 'reset'], True)
    
    def get_rules(self, force_fw_on=True):
        force_fw_on &= not self.get_status()
        if force_fw_on: self.set_status(True)

        rules = self._run_cmd([self.UFW_PATH, 'status', 'numbered'], True)
        if force_fw_on: self.set_status(False)

        return findall(r'\[\s+\d+\]\s*(.*?(?:ALLOW|DENY|LIMIT|REJECT).*?)\s*\n', rules)
    
    def add_rule(self, insert:str, policy:str, direction:str, iface:str, routed:str, logging:str, proto:str, from_ip:str, from_port:str, to_ip:str, to_port:str):
        # ufw [route] [insert NUM] allow|deny|reject|limit [in|out on INTERFACE] [log|log-all] [proto protocol] [from ADDRESS [port PORT]] [to ADDRESS [port PORT]]
        cmd_rule = [self.UFW_PATH]

        # route
        if routed:
            cmd_rule.append('route')
        
        # Insert Number
        if insert:
            cmd_rule.extend(['insert', insert if int(insert)>0 else '0'])
        
        # Policy
        cmd_rule.append(policy)
        
        # Direction
        cmd_rule.append(direction)
        
        # Interface
        if iface:
            cmd_rule.extend(['on', iface])
        
        # Routed on
        '''
        Routed is an interface just like iface,
        if direction on iface is in one way, it MUST be the other way on routed
        eg.: traffic coming in from iface must exit from routed;
        traffic coming in from routed must exit from iface
        '''
        if routed:
            cmd_rule.extend(['out' if direction == 'in' else 'in', 'on', routed])
        
        # Logging
        if logging:
            cmd_rule.append(logging)
        
        # Proto
        if '/tcp' in from_port or '/tcp' in to_port:
            cmd_rule.extend(['proto', 'tcp'])
        elif '/udp' in from_port or '/udp' in to_port:
            cmd_rule.extend(['proto', 'udp'])
        elif proto:
            cmd_rule.extend(['proto', proto])
        
        # From IP
        cmd_rule.extend(['from', from_ip or 'any'])
        # From Port
        if from_port:
            if '/tcp' in from_port:
                from_port = from_port.replace('/tcp', '')
            if '/udp' in from_port:
                from_port = from_port.replace('/udp', '')
            cmd_rule.extend(['port', from_port])
        
        # To IP
        cmd_rule.extend(['to', to_ip or 'any'])
        # To Port
        if to_port:
            if '/tcp' in to_port:
                to_port = to_port.replace('/tcp', '')
            if '/udp' in to_port:
                to_port = to_port.replace('/udp', '')
            cmd_rule.extend(['port', to_port])
        
        # Launch
        rules_before = self.get_rules()
        cmd_rule = list(map(lambda x: x.lower(), cmd_rule))
        cmd = self._run_cmd(cmd_rule, True)
        rules_after = self.get_rules()
        
        return [len(rules_before) != len(rules_after), ' '.join(cmd_rule), cmd] # cmd | ufw result
    
    def delete_rule(self, num:str):
        delete_rule = [self.UFW_PATH, '--force', 'delete', num]        
        return [' '.join(delete_rule), self._run_cmd(delete_rule)] # cmd | ufw result
    
    def get_net_interfaces(self, exclude_iface=''):        
        return sorted([iface for iface in listdir('/sys/class/net') if iface and iface != exclude_iface])
    
    def get_internal_ip(self):
        s = socket(AF_INET, SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    
    def get_known_services(self, sort_by_name=False):
        all_serv = []
        with open('/etc/services') as f:
            lines = filter(lambda x: x and not x.startswith('#'), map(lambda x: x.strip(), f.readlines()))
            for l in lines if not sort_by_name else sorted(lines):
                s = list(map(lambda x: x or '', list(
                    #split string in service [name, port-number, protocol, [description | ''], [comment | '']]
                    search(r'([^\s]+)\s+(\d+)/(\w+)(?:\s+(.*?)\s*(?:#\s*(.*?))?)?\s*$', l).groups())))
                if s[2].lower() not in ['tcp', 'udp']:
                    continue #ufw only supports tcp and udp
                if all_serv and all_serv[-1][0] == s[0]:
                    all_serv[-1][2]='tcp+udp'
                else:
                    all_serv.append(s)
        return all_serv

    def get_listening_report(self):
        return_report = []
        actual_protocol = 'None'
        report_lines = filter(None, self._run_cmd([self.UFW_PATH, 'show', 'listening'], True)\
            .replace('\n   [', '%').split('\n'))
        
        for descomponent_report in report_lines:
            # Set actual protocol
            proto = search(r'((?:ud|tc)p6?):', descomponent_report)
            if proto:
                actual_protocol = proto.group(1).upper()
                continue
            
            descomponent_report = descomponent_report.strip().replace('(', '').replace(')', '')
            
            policy = search(r'] (allow|deny|reject|limit)', descomponent_report)
            policy = policy.group(1).upper() if policy else '-'
            
            descomponent_fields = descomponent_report.split('%')[0].split(' ')
            # Order: protocol % port % address % application % policy
            return_report.append({
                'protocol':actual_protocol,
                'port':descomponent_fields[0],
                'address':descomponent_fields[1],
                'application':descomponent_fields[2],
                'policy':policy
            })
        
        return return_report