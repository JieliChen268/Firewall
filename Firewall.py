import csv

class Firewall():
    def __init__(self, filename):
        self.filename = filename

    """ 
    This method uses generator to iterate rows in cvs file without loading data. 
    When it found the rule in cvs file, it will return the row(object) by yield keyword.
    """
    def get_content(self, direction, protocol, port, ip_address):
        with open(self.filename, 'r') as csvfile:
            datareader = csv.reader(csvfile)
            count = 0
            for row in datareader:
                if self.match(row, direction, protocol, port, ip_address):
                    yield row
                    print('count', count)
                    count += 1
            if count == 0:
                yield 0

    """
    This method is to check whether the input four parameters can match a rule
    in a specific row of cvs file. 
    """
    def match(self, row, direction, protocol, port, ip_address):
        if row[1] != direction:
            return False

        if row[2] != protocol:
            return False

        if '-' in row[3]:
            min_port = row[3].split('-')[0]
            max_port = row[3].split('-')[1]
            if port < min_port or port > max_port:
                return False
        elif row[3] != port:
            return False

        if '-' in row[4]:
            min_ip = row[4].split('-')[0].split('.')
            max_ip = row[4].split('-')[1].split('.')
            ip = ip_address.split('.')
            for i in range(4):
                if ip[i] < min_ip[i] or ip[i] > max_ip[i]:
                    return False
        elif row[4] != ip_address:
            return False
        return True

    """
    This method is to check whether a packet is accept or not
    """
    def accept_packet(self, direction, protocol, port, ip_address):
        g = self.get_content(direction, protocol, port, ip_address)
        val = next(g)
        print('val', val)
        if val == 0:
            return False
        else:
            return True