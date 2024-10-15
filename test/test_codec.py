import psycopg2
import unittest


class TestStringMethods(unittest.TestCase):
    def test_startup_happy_path(self):
        conn = psycopg2.connect(
            dbname="test",
            user="postgres",
            password="supersecret",
            host="127.0.0.1",
            sslmode="disable",
        )
        self.assertIsNotNone(conn)
