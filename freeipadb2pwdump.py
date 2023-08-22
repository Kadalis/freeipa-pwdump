#!/usr/bin/python3

from berkeleydb import db
import sys, base64

def extractPwdump(db):
	items = db.items()

	# First filter
	onlyPersons = list()
	for i in items:
		string = i[1].decode()
		if ("objectClass: person" in string):
			onlyPersons.append(string)

	# Second filter - only persons with ipaNTHash declared
	onlyWithNTHash = list()
	for i in onlyPersons:
		if ("ipaNTHash:: " in i):
			onlyWithNTHash.append(i)

	# let's assume first UserID is 1000
	id = 1000
	for i in onlyWithNTHash:
		lines = i.splitlines()
		uid = domain = nthash = ""
		for k in lines:
			if (not uid and "uid: " in k):
				uid = k.split(" ")[1]
			if (not domain and "krbPrincipalName: " in k):
				domain = k.split("@")[1]
			if (not nthash and "ipaNTHash:: " in k):
				nthash = bytes.hex(base64.b64decode(k.split(" ")[1]))
		if (uid and domain and nthash):
			print(f"{domain}\\{uid}:{id}::{nthash}:::")
			id += 1


def main():
	# open database
	filename = sys.argv[1]
	freeipaDB = db.DB()
	freeipaDB.open(filename)

	if (sys.argv[2] == "pwdump"):
		extractPwdump(freeipaDB)
	elif (sys.argv[2] == "userPassDump"):
		print("Not Implemented")
	else:
		print(f"Usage: {sys.argv[0]} <id2entry.db filepath> <pwdump|userPassDump>")

main()
