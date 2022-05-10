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

from re import sub, compile
from subprocess import Popen, PIPE
from socket import socket, AF_INET,  SOCK_DGRAM
from typing import Union


POL_IN     = 'incoming'
POL_OUT    = 'outgoing'
POL_ROUTED = 'routed'

class Firewall():
    UFW_PATH    = '/usr/sbin/ufw'
    UFW_DEFAULT = '/etc/default/ufw'
    UFW_CONF    = '/etc/ufw/ufw.conf'
    
    def __init__(self):
        pass
    
    def _run_cmd(self, cmd, lang_c=False):
        if lang_c:
            proc = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE, env={'LANG':'C'})
        else:
            proc = Popen(cmd, shell=False, stdout=PIPE, stderr=PIPE)
        stdout,stderr=proc.communicate()
        
        if stderr and not stderr.decode().startswith("WARN") and not stderr.decode().startswith("DEBUG"): # Error
            return stderr.strip().decode('utf-8')
        else: # OK
            return stdout.strip().decode('utf-8')
    
    def get_status(self):
        return ('Status: active' in self._run_cmd([self.UFW_PATH, 'status'], True))
    
    def get_version(self):
        return compile(r'ufw ([\d.]+)').findall(self._run_cmd([self.UFW_PATH, 'version']))[0]

    def get_policy(self, policy:str) -> str:
        if policy == 'incoming':
            ufw_default_policy = self._run_cmd(['grep', 'DEFAULT_INPUT_POLICY', self.UFW_DEFAULT])
        elif policy == 'outgoing':
            ufw_default_policy = self._run_cmd(['grep', 'DEFAULT_OUTPUT_POLICY', self.UFW_DEFAULT])
        elif policy == 'routed':
            ufw_default_policy = int(self._run_cmd(['sysctl', 'net.ipv4.ip_forward']).replace(" ", "").removeprefix('net.ipv4.ip_forward=').strip())
            if not ufw_default_policy: return 'disabled'
            ufw_default_policy = self._run_cmd(['grep', 'DEFAULT_FORWARD_POLICY', self.UFW_DEFAULT])
        
        if 'ACCEPT' in ufw_default_policy:
            return 'allow'
        elif 'DROP' in ufw_default_policy:
            return 'deny'
        elif 'REJECT' in ufw_default_policy:
            return 'reject'
    
    def get_ufw_logging(self):
        ufw_cmd = self._run_cmd(['grep', '^ *LOGLEVEL', self.UFW_CONF])
        return ufw_cmd.split('=')[1].lower().strip('"\'') if ufw_cmd else 'off'
    
    def set_status(self, status:bool):
        if not status:
            cmd = [self.UFW_PATH, 'disable']
        else:
            cmd = [self.UFW_PATH, '--force', 'enable']
        
        self._run_cmd(cmd)
    
    def set_policy(self, value:str, policy:str):
        if value in ['incoming', 'outgoing', 'routed'] and policy in ['allow', 'deny', 'reject']:
            cmd = [self.UFW_PATH, 'default', policy, value]
            self._run_cmd(cmd)
    
    def set_ufw_logging(self, logging:str):
        if logging in ['off', 'low', 'medium', 'high', 'full']:
            self._run_cmd([self.UFW_PATH, 'logging', logging])
    
    def reset_fw(self):
        self._run_cmd([self.UFW_PATH, '--force', 'reset'], True)
    
    def get_rules(self, force_fw_on=False):
        force_fw_on &= not self.get_status()
        if force_fw_on: self.set_status(True)

        rules = self._run_cmd([self.UFW_PATH, 'status', 'numbered'], True)
        if force_fw_on: self.set_status(False)

        lines = rules.split('\n')
        return_rules = []
        
        for line in lines:
            if line and 'ALLOW' in line or 'DENY' in line or 'LIMIT' in line or 'REJECT' in line:
                rule = line.split('] ')
                return_rules.append(' '.join(rule[1].split()))
        
        return return_rules
    
    def get_number_rules(self):
        numb = 0
        rules = self._run_cmd([self.UFW_PATH, 'status', 'numbered'], True)
        lines = rules.split('\n')
        
        for line in lines:
            if line and 'ALLOW' in line or 'DENY' in line or 'LIMIT' in line or 'REJECT' in line:
                numb = numb + 1
        
        return numb
    
    def add_rule(self, insert:str, policy:str, direction:str, iface:str, routed:str, logging:str, proto:str, from_ip:str, from_port:str, to_ip:str, to_port:str) -> tuple[bool, str, str]:
        # ufw [route] [insert NUM] allow|deny|reject|limit [in|out on INTERFACE] [log|log-all] [proto protocol] [from ADDRESS [port PORT]] [to ADDRESS [port PORT]]
        cmd_rule = [self.UFW_PATH]
        
        insert = insert.lower()
        policy = policy.lower()
        direction = direction.lower()
        iface = iface.lower()
        routed = routed.lower()
        logging = logging.lower()
        proto = proto.lower()
        from_ip = from_ip.lower()
        from_port = from_port.lower()
        to_ip = to_ip.lower()
        to_port = to_port.lower()

        # route
        if routed:
            cmd_rule.append('route')
        
        # Insert Number
        if insert:
            cmd_rule.extend(['insert', str(int(insert))])
        
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
        eg.: traffic coming in iface must exit from routed;
        traffic coming in from routed must exit from iface
        '''
        if routed:
            if direction == 'in':
                cmd_rule.extend(['out', 'on', routed])
            else:
                cmd_rule.extend(['in', 'on', routed])
        
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
        cmd_rule.extend(['from', from_ip if from_ip else 'any'])
        # From Port
        if from_port:
            if '/tcp' in from_port:
                from_port = from_port.replace('/tcp', '')
            if '/udp' in from_port:
                from_port = from_port.replace('/udp', '')
            cmd_rule.extend(['port', from_port])
        
        # To IP
        cmd_rule.extend(['to', to_ip if to_ip else 'any'])
        # To Port
        if to_port:
            if '/tcp' in to_port:
                to_port = to_port.replace('/tcp', '')
            if '/udp' in to_port:
                to_port = to_port.replace('/udp', '')
            cmd_rule.extend(['port', to_port])
        
        # Launch
        rules_before = self.get_rules(True)

        cmd = self._run_cmd(cmd_rule, True)
        rules_after = self.get_rules(True)

        result = [len(rules_before) != len(rules_after)]
        result.append(' '.join(cmd_rule))
        result.append(cmd)
        
        return result # cmd | ufw result
    
    def delete_rule(self, num: Union[str, int]):
        delete_rule = [self.UFW_PATH, '--force', 'delete', str(num)]
        cmd = self._run_cmd(delete_rule)
        
        result = []
        result.append(' '.join(delete_rule))
        result.append(cmd)
        
        return result # cmd | ufw result
    
    def get_net_interfaces(self, exclude_iface=''):        
        all_faces = [iface for iface in self._run_cmd(['ls', '/sys/class/net']).split('\n') if iface]

        if exclude_iface:
            try:
                all_faces.remove(exclude_iface)
            except Exception:
                pass
        
        return all_faces
    
    def get_internal_ip(self):
        s = socket(AF_INET, SOCK_DGRAM)
        s.settimeout(0)
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    
    def get_known_services(self, sort_by_name=False) -> list[tuple[str,str,str,str,str]]:
        all_serv = []
        with open('/etc/services') as f:
            for l in f.readlines() if not sort_by_name else sorted(f.readlines()):
                l = l.strip()
                if not l or l.startswith('#'): continue
                s = l.split('#', 1)
                if len(s)==1: s.append('') #service has no comment :(
                s = [*sub('[\s\\t]+', ' ', s[0]).split(' ', 2), s[1]] #split string in service [name, port, [description | ''], comment]
                s = list(map(lambda x: x.strip(), [s[0], *s[1].split('/'), *([s[2],s[3]] if len(s)>3 else ['',s[2]])])) #split string in service [name, port-number, protocol, [description | ''], comment]
                if s[2].lower() not in ['tcp', 'udp']: continue #ufw only supports tcp and udp
                if all_serv and all_serv[-1][0] == s[0]: all_serv[-1][2]='' #ip port needs both protocols we simply don't select one
                else: all_serv.append(s)
        return all_serv

    def get_listening_report(self):
        return_report = []
        actual_protocol = 'None'
        report_lines = self._run_cmd([self.UFW_PATH, 'show', 'listening'], True).replace('\n   [', '%').split('\n')
        
        for descomponent_report in report_lines:
            # Set actual protocol
            if not descomponent_report:
                continue
            if 'tcp6:' in descomponent_report:
                actual_protocol = 'TCP6'
                continue
            if 'tcp:' in descomponent_report:
                actual_protocol = 'TCP'
                continue
            if 'udp6:' in descomponent_report:
                actual_protocol = 'UDP6'
                continue
            if 'udp:' in descomponent_report:
                actual_protocol = 'UDP'
                continue
            
            policy = 'None'
            descomponent_report = descomponent_report.strip().replace('(', '').replace(')', '')
            
            if ']' in descomponent_report:
                descomponent_policy = descomponent_report.split(']')
                if 'allow' in descomponent_policy[1]:
                    policy = 'allow'
                elif 'deny' in descomponent_policy[1]:
                    policy = 'deny'
                elif 'reject' in descomponent_policy[1]:
                    policy = 'reject'
                elif 'limit' in descomponent_policy[1]:
                    policy = 'limit'
            
            descomponent_report = descomponent_report.split('%')
            descomponent_fields = descomponent_report[0].split(' ')
            # Order: protocol % port % address % application % policy
            return_report.append({'protocol':actual_protocol, 'port':descomponent_fields[0], 'address':descomponent_fields[1], 'application':descomponent_fields[2], 'policy':policy})
        
        return return_report