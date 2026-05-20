class NetEvent:
    def __init__(self, process, connection):
        self.process = process
        self.connection = connection
        self.occurrences = 1
        self.regularity = 0
