from unittest import TestCase
from Firewall import Firewall
import unittest

class FirewallTest(TestCase):

    def setUp(self):
        self.fw = Firewall('/Users/jielichen/PycharmProjects/Firewall/fw.csv')

    #@unittest.skip
    def test_match(self):
        records = [
                   ['1','inbound', 'tcp', '80', '192.168.1.2'],
                   ['2', 'inbound', 'udp', '53', '192.168.1.1-192.168.2.5'],
                   ['3', 'outbound', 'tcp', '10000-20000', '192.168.10.11'],
                   ['4', 'inbound', 'tcp', '60000-65535', '192.178.10.11-255.255.255.255'],
                   ['5', 'outbound', 'udp', '1-59999', '0.0.0.0-192.78.43.56'],
                   ['6', 'outbound', 'udp', '1000-2000', '52.12.48.92'],
                   ['7', 'inbound', 'tcp', '8990', '192.78.43.56'],
                   ]
        
        rows1 = [
                 ["inbound", "tcp", '80', "192.168.1.2"],
                 ["inbound", "udp", '53', "192.168.2.1"],
                 ["outbound", "tcp", '10234', "192.168.10.11"],
                 ['inbound','tcp','65535', '255.255.255.255'],
                 ['outbound', 'udp', '1', '0.0.0.0']
                 ]

        rows2 = [
                 ["inbound", "tcp", '81', "192.168.1.2"],
                 ["inbound", "udp", '24', "52.12.48.92"]
                ]

        for i in range(5):
            result1 = self.fw.match(records[i], rows1[i][0], rows1[i][1], rows1[i][2], rows1[i][3])
            self.assertEqual(True, result1)
        for i in range(1):
            result2 = self.fw.match(records[i], rows2[i][0],rows2[i][1],rows2[i][2],rows2[i][3])
            self.assertEqual(False, result2)

    #@unittest.skip
    def test_get_content(self):
        rows1 = [
                 ["inbound", "tcp", '80', "192.168.1.2"],
                 ["inbound", "udp", '53', "192.168.2.1"],
                 ["outbound", "tcp", '10234', "192.168.10.11"],
                 ['inbound','tcp','65535', '255.255.255.255'],
                 ['outbound', 'udp', '1', '0.0.0.0']
                 ]

        rows2 = [
                 ["inbound", "tcp", '81', "192.168.1.2"],
                 ["inbound", "udp", '24', "52.12.48.92"]
                ]

        g1 = self.fw.get_content(rows1[0][0],rows1[0][1],rows1[0][2],rows1[0][3])
        result1 = next(g1)
        self.assertEqual(['1', 'inbound', 'tcp', '80', '192.168.1.2'], result1)

        g2 = self.fw.get_content(rows1[1][0],rows1[1][1],rows1[1][2],rows1[1][3])
        result2 = next(g2)
        self.assertEqual(['3', 'inbound', 'udp', '53', '192.168.1.1-192.168.2.5'], result2)

        g3 = self.fw.get_content(rows1[2][0],rows1[2][1],rows1[2][2],rows1[2][3])
        result3 = next(g3)
        self.assertEqual(['2', 'outbound', 'tcp', '10000-20000', '192.168.10.11'], result3)

        g4 = self.fw.get_content(rows2[0][0],rows2[0][1],rows2[0][2],rows2[0][3])
        result4 = next(g4)
        self.assertEqual(0, result4)

        g5 = self.fw.get_content(rows2[1][0],rows2[1][1],rows2[1][2],rows2[1][3])
        result5 = next(g5)
        self.assertEqual(0, result5)


    #@unittest.skip
    def test_accept_packet(self):
        rows1 = [
                ["inbound", "tcp", '80', "192.168.1.2"],
                ["inbound", "udp", '53', "192.168.2.1"],
                ["outbound", "tcp", '10234', "192.168.10.11"],
                ['outbound', 'udp', '1', '0.0.0.0'],
                ['inbound','tcp','65535', '255.255.255.255']
                ]
        
        rows2 = [
                ["inbound", "tcp", '81', "192.168.1.2"],
                 ["inbound", "udp", '24', "52.12.48.92"]
                ]

        for row in rows1:
            result1 = self.fw.accept_packet(row[0],row[1],row[2],row[3])
            self.assertEqual(True, result1)

        for row in rows2:
            result2 = self.fw.accept_packet(row[0],row[1], row[2],row[3])
            self.assertEqual(False, result2)
