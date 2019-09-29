Note: Code written for Python 3.5.2

Design Decisions
================

To store rules, I first created four arrays, corresponding to the four combinations of direction and protocol.
Within each array, I stored rules as pairs of ranges, where the first element is the range of ports and the
second is the range of IP addresses. I stored IP addresses as 32 bit integers, to allow for quick range
comparisons. I then sorted these arrays by the extrema of the ranges, allowing me to perform binary search within
an array to find a pair of ranges that matches the port and IP of each packet I analyze (if one exists).

Testing
=======

To test my firewall, I created a CSV file with a variety of rule types, then outlined a large number of test
packets in testFirewall.py to be tested against these rules. I selected edge cases to check for overlapping
ranges, IP addresses which are only properly ordered when converted to 32 bit integers, different rules with 
one identical range, rules covering the full list of ranges, rules allowing for maximum and minimum possible
values, and more.

Potential Improvements
======================

Given unlimited memory, this computation could be sped up drastically by marking acceptable port/IP combos
in a boolean matrix of size (4294967295, 65535), as we could check each packet in O(1) time. However, this is quite
a sacrifice, as it would require us to allocate nearly 300 trillion bits (assuming each boolean can be stored
in one bit).

One more practical improvement would be to combine intersecting ranges. With a large number of rules, it's
quite possible that certain rules could be redundant, so we could combine rules (or sections of rules) that
verify the same packets. This could slow down the firewall initialization quite a bit, but would only help
to speed up the checks for individual packets. In reality, I would assume that the computation costs for 
checking packets are much more important to minimize than the initialization cost.

Team Interest
=============

The data team is the role that interests me the most. I love working with large datasets and dealing with
the challenges that accompany them.