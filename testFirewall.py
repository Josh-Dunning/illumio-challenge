
# Josh Dunning
# 9/29/19
# Illumio

from firewall import Firewall

true_inputs = [
	('outbound', 'tcp', 10,	'192.168.1.2'),
	('inbound', 'tcp', 20,	'192.168.1.5'),
	('inbound', 'tcp', 22,	'192.168.1.5'),
	('inbound', 'udp', 30,	'192.168.1.5'),
	('outbound', 'udp', 25,	'192.168.1.12'),
	('outbound', 'udp', 25,	'192.168.1.200'),
	('inbound', 'tcp', 25,	'192.168.2.0'),
	('inbound', 'udp', 25,	'192.168.2.4'),
	('inbound', 'tcp', 25,	'192.168.2.5'),
	('outbound', 'tcp', 29,	'192.200.1.1'),
	('outbound', 'tcp', 30,	'192.20.10.15'),
	('inbound', 'udp', 30,	'192.20.10.200'),
	('inbound', 'udp', 30,	'192.20.12.0'),
	('inbound', 'tcp', 30,	'192.21.0.0'),
	('outbound', 'tcp', 30,	'192.21.240.240'),
	('inbound', 'udp', 30,	'192.200.0.1'),
	('inbound', 'tcp', 32,	'192.20.10.10'),
	('outbound', 'udp', 58,	'192.168.1.122'),
	('outbound', 'udp', 99,	'255.255.255.255'),
	('outbound', 'udp', 100,'0.0.0.0'),
	('outbound', 'udp', 100,'255.255.255.255'),
	('outbound', 'udp', 100,'1.2.3.4'),
]

false_inputs = [
	('inbound', 'udp', 9,	'192.168.1.2'),
	('outbound', 'tcp', 11,	'192.168.1.2'),
	('inbound', 'udp', 10,	'192.168.1.1'),
	('outbound', 'udp', 10,	'192.168.1.3'),
	('inbound', 'tcp', 19,	'192.168.1.5'),
	('outbound', 'tcp', 20,	'192.168.1.4'),
	('inbound', 'udp', 25,	'192.168.1.1'),
	('outbound', 'udp', 25,	'192.168.1.11'),
	('inbound', 'tcp', 25,	'192.168.2.6'),
	('inbound', 'tcp', 29,	'192.20.9.10'),
	('outbound', 'tcp', 30,	'192.19.100.100'),
	('outbound', 'udp', 31,	'192.200.2.0'),
	('inbound', 'tcp', 58,	'192.168.1.9'),
	('outbound', 'udp', 99,	'0.0.0.0'),
	('outbound', 'udp', 99,'255.255.255.254'),
]

fw = Firewall('./test1.csv')

for args in true_inputs:
	if not fw.accept_packet(*args):
		print ("Failed! VALID arg {} returned FALSE".format(args))

for args in false_inputs:
	if fw.accept_packet(*args):
		print ("Failed! INVALID arg {} returned TRUE".format(args))