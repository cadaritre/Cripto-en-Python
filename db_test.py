#!/usr/bin/python
# -*- coding: utf-8 -*-
# Nombre por lo pronto es "Lapis Mens"

import mysql.connector

print("Iniciando script...")

try:
    mydb = mysql.connector.connect(
        host="localhost",      # Solo la IP, sin el puerto
        port=3306,             # Puerto como parámetro aparte
        user="root",
        password="root",
        database="Crypto",
        connection_timeout=5
    )
    print("Connection successful!")
    mydb.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
except Exception as e:
    print(f"Otro error: {e}")