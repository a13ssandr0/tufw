#!/usr/bin/env python
from errno import ENOENT
from os import getuid, execlp
from sys import executable, argv
from dialog import Dialog
from .firewall import *


def elevate():
	if getuid() != 0:
		# if we are not root we replace current shell with an elevated one
		try:
			execlp('sudo', *['sudo', 'LANG=C', executable, *argv])
		except OSError as e:
			if e.errno != ENOENT:
				raise


def rotate(input, n=1):
	return input[n:] + input[:n]


def get_tuple_with_value(list: list[tuple], index: int, value):
	for t in list:
		if t[index] == value:
			return t
	raise ValueError(f'Provided list has no item with value {value}')


def main():
	elevate()

	d = Dialog(autowidgetsize=True)
	ufw = Firewall()

	while True:
		ports = ufw.get_rules(True)
		list_elems = [
			['Firewall', 'Enabled' if ufw.get_status() else 'Disabled'],
			['', ''],['', ''],
			['IN policy', ufw.get_policy(POL_IN).upper()],
			['OUT policy', ufw.get_policy(POL_OUT).upper()],
			['ROUTED policy', ufw.get_policy(POL_ROUTED).upper()],
			['Logging', ufw.get_ufw_logging().capitalize()],
			['', ''],
			*[[str(k).rjust(13),ports[k-1]] for k in range(1,len(ports)+1)],
			['', ''],
			['[ + ]'.rjust(13), 'Add rule'],
			['[ - ]'.rjust(13), 'Delete rule'],
			['', ''],
			['Report', 'List active connections'],
			['Reset', 'Restore default firewall configuration']
		]
		response = d.menu(title='Ufw firewall configuration', text=f'Computer IP: {ufw.get_internal_ip()}', backtitle=f'Ufw version: {ufw.get_version()}', extra_button=True, extra_label='Reload', cancel_label='Exit', choices=list_elems)
		if response[0] == d.CANCEL: break
		elif response[0] == d.EXTRA:
			d.infobox(text='Reloading firewall', height=4, width=30)
			if ufw.get_status():
				ufw.set_status(False)
				ufw.set_status(True)
				d.infobox(text='Firewall reloaded', height=4, width=30)
			else:
				d.infobox(text='Firewall not enabled (skipping reload)', height=4, width=50)
		else:
			response = response[1].strip()
			if response == 'Firewall': ufw.set_status(not ufw.get_status())

			elif response == '[ + ]':
				application =   'Custom'
				insert =        '0'
				policies =      ['ALLOW', 'DENY', 'REJECT', 'LIMIT']
				directions =    ['IN', 'OUT', 'BOTH']
				interfaces =    ['All', *ufw.get_net_interfaces()]
				routed_ifaces = ['None', *ufw.get_net_interfaces()]
				log_level =     ['No', 'Yes', 'All']
				proto =         ['Both', 'TCP', 'UDP']
				from_ip = from_port = to_ip = to_port = ''
				while True:
					rule= {
						'Application': application,
						'Insert':      insert,
						'Policy':      policies[0],
						'Direction':   directions[0],
						'Inteface':    interfaces[0],
						'Routed to':   routed_ifaces[0],
						'Log':         log_level[0],
						'Protocol':    proto[0],
						'From IP':     from_ip,
						'From port':   from_port,
						'To IP':       to_ip,
						'To port':     to_port,
					}
					response1 = d.menu(title='New rule', backtitle='Ufw rule creation', text='Insert rule details', extra_button=True, extra_label='Save', choices=list(rule.items()), width=57)
					if response1[0] == d.CANCEL or response1[0] == d.ESC: break
					elif response1[0] == d.EXTRA:
						res = ufw.add_rule(insert=rule['Insert'] if int(rule['Insert']) else '',
									policy=rule['Policy'],
								direction=rule['Direction'],
									iface=rule['Inteface'] if rule['Inteface'] != 'All' else '',
									routed=rule['Routed to'] if rule['Routed to'] != 'None' else '',
									logging='log-all' if rule['Log'] == 'All' else 'log' if rule['Log'] == 'Yes' else '',
									proto=rule['Protocol'] if rule['Protocol'] != 'Both' else '',
									from_ip=rule['From IP'],
								from_port=rule['From port'],
									to_ip=rule['To IP'],
									to_port=rule['To port'])
						if not res[0]: d.msgbox(text=f'Command:\n{res[1]}\n\nReturned:\n{res[2]}', title='Error')
						break
					else:
						response1 = response1[1].strip()
						if response1 == 'Application':
							services = ufw.get_known_services(True)
							list_elems2 = [[s[0], '{:>5} {:<10}{}'.format(s[1], s[2] if s[2] else "tcp+udp", s[4] if s[4] else s[3])] for s in services]
							response2 = d.menu(title='Application', backtitle='Ufw rule creation', text='Select an application from the list or create a new one', choices=list_elems2)
							if response2[0] == d.OK:
								service = get_tuple_with_value(services, 0, response2[1])
								application = service[0]
								to_port = service[1]
								proto = ['TCP', 'UDP', 'Both'] if service[2] == 'tcp' else ['UDP', 'Both', 'TCP'] if service[2] == 'tcp' else ['Both', 'TCP', 'UDP']
						elif response1 == 'Insert':
							response2 = d.rangebox(title='Insert', backtitle='Ufw rule creation', text='Select where to insert rule, default (0) is at the end.\nUse arrows up/down to decrease/increase number', width=60, min=0, max=ufw.get_number_rules(), init=int(insert))
							if response2[0] == d.OK:
								insert=str(response2[1])
						elif response1 == 'Policy':    policies=rotate(policies)
						elif response1 == 'Direction': directions=rotate(directions)
						elif response1 == 'Inteface':  interfaces=rotate(interfaces)
						elif response1 == 'Routed to': routed_ifaces=rotate(routed_ifaces)
						elif response1 == 'Log':       log_level=rotate(log_level)
						elif response1 == 'Protocol':  proto=rotate(proto)
						elif response1 == 'From IP':
							response2 = d.inputbox(text='Source IP', init=from_ip)
							if response2[0] == d.OK: from_ip=response2[1]
						elif response1 == 'From port':
							response2 = d.inputbox(text='Source port', init=from_port)
							if response2[0] == d.OK: from_port=response2[1]
						elif response1 == 'To IP':
							response2 = d.inputbox(text='Destination IP', init=to_ip)
							if response2[0] == d.OK: to_ip=response2[1]
						elif response1 == 'To port':
							response2 = d.inputbox(text='Destination port', init=to_port)
							if response2[0] == d.OK: to_port=response2[1]

			elif response == '[ - ]':
				while True:
					ports = ufw.get_rules(True)
					list_elems1 = [[str(k),ports[k-1], False] for k in range(1,len(ports)+1)]
					if not list_elems1: break
					response1 = d.checklist(title='Delete rule(s)', text='Select rule(s) to delete', extra_button=True, extra_label='Delete all', choices=list_elems1)
					if response1[0] == d.CANCEL: break
					elif response1[0] == d.OK or response1[0] == d.EXTRA:
						if response1[0] == d.EXTRA: response1=[d.EXTRA, [str(i) for i in range(1,len(ports)+1)]]
						if not response1:
							d.msgbox(text='No rules selected', height=6, width=30)
						elif d.yesno(title='Warning!!', text=f"Are you sure you want to delete {len(response1[1])} rule{'' if len(response1[1])==1 else 's'}?", default_button='No') == d.OK:
							d.gauge_start(text='', percent=0, title='Deleting rules...', width=60)
							num_r = len(response1[1])
							for rule in reversed(response1[1]):
								d.gauge_update(percent=int(100-(int(rule)-1)*100/num_r), text=f'Deleting rule: {ports[int(rule)-1]}', update_text=True)
								ufw.delete_rule(rule)
							d.gauge_stop()
							d.msgbox(title='Rules deleted', text='Deleted:\n' + '\n'.join([e[1] for e in list_elems1 if e[0] in response1[1]]))

			elif response == 'Report':
				d.scrollbox(title='Active connections', text=
					'Protocol    Port   Address           Policy    Application\n\n' +
					'\n'.join(['{:<12}{:>5}  {:<18}{:<10}{}'.format(l['protocol'], l['port'], l['address'], l['policy'], l['application']) for l in sorted(ufw.get_listening_report(), key= lambda item: int(item['port']))]))

			elif response == 'IN policy':
				pol = d.menu(title='IN policy', text='Select default policy for inbound connections', choices=[['ALLOW',''], ['DENY',''], ['REJECT','']])
				if pol[0] == d.OK: ufw.set_policy(POL_IN, pol[1].lower())

			elif response == 'OUT policy':
				pol = d.menu(title='OUT policy', text='Select default policy for outbound connections', choices=[['ALLOW',''], ['DENY',''], ['REJECT','']])
				if pol[0] == d.OK: ufw.set_policy(POL_OUT, pol[1].lower())

			elif response == 'ROUTED policy' and ufw.get_policy(POL_ROUTED)!='disabled':
				pol = d.menu(title='ROUTED policy', text='Select default policy for routed connections', choices=[['ALLOW',''], ['DENY',''], ['REJECT','']])
				if pol[0] == d.OK: ufw.set_policy(POL_ROUTED, pol[1].lower())

			elif response == 'Logging':
				log_level = d.menu(title='ROUTED policy', text='Select default policy for routed connections', choices=[['Full',''], ['High',''], ['Medium',''], ['Low', ''], ['Off', '']])
				if log_level[0] == d.OK: ufw.set_ufw_logging(log_level[1].lower())

			elif response == 'Reset':
				if d.yesno(title='Warning!!', text='Are you sure you want to reset the firewall to the default settings?', default_button='No') == d.OK:
					if d.yesno(title='Warning!!', text='Are you REALLY sure you want to reset the firewall to the default settings?', default_button='No') == d.OK:
						d.infobox(text='Resetting firewall')
						ufw.reset_fw()

	d.clear()


if __name__ == "__main__":
	main()