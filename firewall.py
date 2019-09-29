
# Josh Dunning
# 9/29/19
# Illumio

# Reference materials:
#
# # Reading and Writing CSV Files in Python
# # https://realpython.com/python-csv/
#
# # Strange character while reading a CSV file
# # https://stackoverflow.com/questions/50228008/strange-character-while-reading-a-csv-file
#
# # Convert an IP string to a number and vice versa
# # https://stackoverflow.com/questions/9590965/convert-an-ip-string-to-a-number-and-vice-versa

import csv
import socket, struct

class Firewall:
	def __init__(self, csv_filepath):
		"""
		Read the CSV file at the provided path and create a rule for each entry.
		Input: 
			csv_filepath - String specifying the path to the CSV file
		Output: 
			None
		"""
		self.firewall_rules = {
			'inbound': {
				'tcp': [],
				'udp': [],
			},
			'outbound': {
				'tcp': [],
				'udp': [],
			}
		}

		# Setup valid ranges for all rules
		with open(csv_filepath, encoding="utf-8-sig") as file:
		    rules = csv.reader(file, delimiter=',')
		    for direction, protocol, port, ip_address in rules:
		    	self.firewall_rules[direction][protocol].append((self.raw_port_to_range(port), self.raw_ip_to_range(ip_address)))

		# Sort rules by extrema of ranges, to make binary search possible
		for direction in self.firewall_rules.values():
			for protocol, rules in direction.items():
				direction[protocol] = sorted(rules, key=lambda rule: (rule[0][0], rule[0][-1], rule[1][0], rule[1][-1]))

	def accept_packet(self, direction, protocol, port, ip_address):
		"""
		Check if traffic with the provided properties should be allowed through our firewall.
		Input: 
			direction 	- String specifying whether the traffic is inbound or outbound
			protocol 	- String specifying whether the protocol is tcp or udp
			port 		- Integer specifying the port of the packet
			ip_address 	- String specifying the IP address of the packet
		Output: 
			True 	if there exists a rule in our firewall which matches the packet
			False 	otherwise
		"""
		return self.rule_binary_search(self.firewall_rules[direction][protocol], port, self.ip_to_32bit_int(ip_address))

	def rule_binary_search(self, rules, port, ip):
		"""
		Perform binary search through a list of rules for one matching the provided port and ip.
		Input: 
			rules 		- An array of rules to be checked
			port 		- Integer specifying the port of the packet
			ip 			- 32 bit number specifying the IP address of the packet
		Output: 
			True 	if there exists a rule in our firewall which matches the packet
			False 	otherwise
		"""
		if not rules:
			return False

		mid = len(rules) // 2
		port_range, ip_range = rules[mid]

		if port in port_range:
			if ip in ip_range:
				return True
			else:
				if ip < ip_range[0]:
					return self.rule_binary_search(rules[:mid], port, ip)
				else:
					return self.rule_binary_search(rules[mid+1:], port, ip)
		elif port < port_range[0]:
			return self.rule_binary_search(rules[:mid], port, ip)
		else: 
			return self.rule_binary_search(rules[mid+1:], port, ip)


	def raw_port_to_range(self, raw_port):
		"""
		Convert a string port representation to the corresponding integer range of ports.
		Input: 
			raw_port - String specifying a port or port range
		Output: 
			A range object of all valid ports defined by "raw_port"
		"""
		port_limits = list(map(lambda port: int(port), raw_port.split("-")))
		upper_bound = port_limits[1] if len(port_limits) == 2 else port_limits[0]
		return range(port_limits[0], upper_bound + 1)

	def raw_ip_to_range(self, raw_ip):
		"""
		Convert a string IP representation to the corresponding 32 bit integer range of IPs.
		Input: 
			raw_port - String specifying an IP address or address range
		Output: 
			A range object of all valid IP addresses (in 32 bit int form) defined by "raw_ip"
		"""
		ip_limits = list(map(lambda ip: self.ip_to_32bit_int(ip), raw_ip.split("-")))
		upper_bound = ip_limits[1] if len(ip_limits) == 2 else ip_limits[0]
		return range(ip_limits[0], upper_bound + 1)

	def ip_to_32bit_int(self, ip):
		"""
		Convert a single IP string to a 32 bit integer.
		Input: 
			ip - String specifying the IP address of the packet
		Output: 
			"ip" as a 32 bit integer
		"""
		return struct.unpack("!L", socket.inet_aton(ip))[0]


		