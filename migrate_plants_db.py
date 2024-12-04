"""
NOTE: I created this file because a plant from an older version of the program did not work well with 
the new functionality I added (primarily deletion and account management). This program nuked the 
database and created a fresh one that would work with the main program.

If you wish to locally host the program and want a fresh start (deleting the test account I created), 
or if there is a problem with the database, feel free to run this file! Note that all data will be 
lost, including your plants and your account.
"""

import sqlite3
import os


def reset_and_init_db():

    try:
        os.remove("plants.db")
        print("Old database deleted.")
    except FileNotFoundError:
        print("No existing database found. Proceeding anyways.")

    conn = sqlite3.connect("plants.db")
    c = conn.cursor()

    c.execute(
        """CREATE TABLE IF NOT EXISTS users
            (username TEXT PRIMARY KEY, 
            password_hash TEXT,
            salt TEXT)"""
    )

    c.execute(
        """CREATE TABLE IF NOT EXISTS plants
            (name TEXT, species TEXT, last_watered DATE, 
            last_fertilized DATE, notes TEXT, username TEXT,
            FOREIGN KEY (username) REFERENCES users(username))"""
    )

    c.execute(
        """CREATE TABLE IF NOT EXISTS photos
            (plant_name TEXT, photo BLOB, date DATE, notes TEXT, 
            username TEXT,
            FOREIGN KEY (username) REFERENCES users(username))"""
    )

    conn.commit()
    conn.close()
    print("New 'plants.db' created and initialized.")


reset_and_init_db()
