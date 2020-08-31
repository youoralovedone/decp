import sqlite3


# member db must be named members.db and located in the same directory as decp.py
class sqlite3_wrapper():
    def __init__(self):
        # connect to members.db
        self.conn = sqlite3.connect("members.db")
        self.conn.row_factory = sqlite3.Row
        self.c = self.conn.cursor()

    def execute(self, query, *argv):
        self.c.execute(query, argv)
        self.conn.commit()
        return [dict(row) for row in self.c.fetchall()]

    def close(self):
        # close connection to database
        self.conn.close()
