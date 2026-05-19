class Stats:

    def __init__(self):

        self.total = 0
        self.scanned = 0
        self.open_hosts = 0
        self.matched = 0
        self.cdns = {}

    def add_cdn(self, cdn):

        if cdn not in self.cdns:
            self.cdns[cdn] = 0

        self.cdns[cdn] += 1
