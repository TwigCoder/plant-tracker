import streamlit as st
import pandas as pd
from datetime import datetime
from PIL import Image
import io
import sqlite3
import hashlib
import secrets


def init_db():
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)"""
    )
    c.execute("PRAGMA table_info(plants)")
    columns = [column[1] for column in c.fetchall()]
    if "username" not in columns:
        c.execute(
            """CREATE TABLE IF NOT EXISTS plants_new (name TEXT, species TEXT, last_watered DATE, last_fertilized DATE, notes TEXT, username TEXT, FOREIGN KEY (username) REFERENCES users(username))"""
        )
        c.execute(
            """INSERT INTO plants_new SELECT name, species, last_watered, last_fertilized, notes, NULL FROM plants"""
        )
        c.execute("DROP TABLE plants")
        c.execute("ALTER TABLE plants_new RENAME TO plants")
    c.execute("PRAGMA table_info(photos)")
    columns = [column[1] for column in c.fetchall()]
    if "username" not in columns:
        c.execute(
            """CREATE TABLE IF NOT EXISTS photos_new (plant_name TEXT, photo BLOB, date DATE, notes TEXT, username TEXT, FOREIGN KEY (username) REFERENCES users(username))"""
        )
        c.execute(
            """INSERT INTO photos_new SELECT plant_name, photo, date, notes, NULL FROM photos"""
        )
        c.execute("DROP TABLE photos")
        c.execute("ALTER TABLE photos_new RENAME TO photos")
    conn.commit()
    conn.close()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hash_obj.hex(), salt


def verify_password(password, hash_value, salt):
    new_hash, _ = hash_password(password, salt)
    return new_hash == hash_value


def register_user(username, password):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (username,))
    if c.fetchone() is not None:
        conn.close()
        return False
    password_hash, salt = hash_password(password)
    c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password_hash, salt))
    conn.commit()
    conn.close()
    return True


def login_user(username, password):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result is None:
        return False
    stored_hash, salt = result
    return verify_password(password, stored_hash, salt)


def add_plant(name, species, last_watered, last_fertilized, notes, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """INSERT INTO plants VALUES (?,?,?,?,?,?)""",
        (name, species, last_watered, last_fertilized, notes, username),
    )
    conn.commit()
    conn.close()


def get_plants(username):
    conn = sqlite3.connect("plants.db")
    df = pd.read_sql_query(
        "SELECT * FROM plants WHERE username = ? OR username IS NULL",
        conn,
        params=(username,),
    )
    conn.close()
    return df


def add_photo(plant_name, photo, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """INSERT INTO photos VALUES (?,?,?,?,?)""",
        (plant_name, photo, datetime.now().date(), "", username),
    )
    conn.commit()
    conn.close()


def get_photos(plant_name, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """SELECT rowid, photo, date, notes FROM photos WHERE plant_name = ? AND (username = ? OR username IS NULL) ORDER BY date DESC""",
        (plant_name, username),
    )
    photos = c.fetchall()
    conn.close()
    return photos


def delete_plant(name, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute("DELETE FROM plants WHERE name = ? AND username = ?", (name, username))
    c.execute(
        "DELETE FROM photos WHERE plant_name = ? AND username = ?", (name, username)
    )
    conn.commit()
    conn.close()


def update_plant(name, field, value, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    query = f"UPDATE plants SET {field} = ? WHERE name = ? AND username = ?"
    c.execute(query, (value, name, username))
    conn.commit()
    conn.close()


def delete_photo(plant_name, photo_date, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """SELECT rowid FROM photos WHERE plant_name = ? AND date = ? AND username = ?""",
        (plant_name, photo_date, username),
    )
    row_id = c.fetchone()[0]
    c.execute("""DELETE FROM photos WHERE rowid = ?""", (row_id,))
    conn.commit()
    conn.close()


def update_photo_notes(plant_name, photo_date, notes, username):
    conn = sqlite3.connect("plants.db")
    c = conn.cursor()
    c.execute(
        """SELECT rowid FROM photos WHERE plant_name = ? AND date = ? AND username = ?""",
        (plant_name, photo_date, username),
    )
    row_id = c.fetchone()[0]
    c.execute("""UPDATE photos SET notes = ? WHERE rowid = ?""", (notes, row_id))
    conn.commit()
    conn.close()


init_db()

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None

st.title("Plant Care Tracker")

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        st.header("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input(
            "Password", type="password", key="login_password"
        )
        if st.button("Login"):
            if login_user(login_username, login_password):
                st.session_state.logged_in = True
                st.session_state.username = login_username
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid username or password")

    with tab2:
        st.header("Register")
        reg_username = st.text_input("Username", key="reg_username")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        reg_confirm_password = st.text_input("Confirm Password", type="password")
        if st.button("Register"):
            if reg_password != reg_confirm_password:
                st.error("Passwords do not match")
            elif len(reg_password) < 6:
                st.error("Password must be at least 6 characters long")
            else:
                if register_user(reg_username, reg_password):
                    st.success("Registration successful! Please login.")
                else:
                    st.error("Username already exists")

else:
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    menu = st.sidebar.selectbox("Menu", ["Add Plant", "View/Update Plants"])

    if menu == "Add Plant":
        st.header("Add New Plant")
        name = st.text_input("Plant Name")
        species = st.text_input("Species")
        last_watered = st.date_input("Last Watered")
        last_fertilized = st.date_input("Last Fertilized")
        notes = st.text_area("Care Notes")

        if st.button("Add Plant"):
            add_plant(
                name,
                species,
                last_watered,
                last_fertilized,
                notes,
                st.session_state.username,
            )
            st.success("Plant added successfully!")

    elif menu == "View/Update Plants":
        st.header("Your Plants")
        plants_df = get_plants(st.session_state.username)

        if not plants_df.empty:
            selected_plant = st.selectbox("Select Plant", plants_df["name"].tolist())
            plant_data = plants_df[plants_df["name"] == selected_plant].iloc[0]

            if st.button("Delete Plant"):
                delete_plant(selected_plant, st.session_state.username)
                st.success("Plant deleted!")
                st.rerun()

            col1, col2 = st.columns(2)

            with col1:
                if st.button("Water Plant"):
                    update_plant(
                        selected_plant,
                        "last_watered",
                        datetime.now().date(),
                        st.session_state.username,
                    )
                    st.success("Watering recorded!")

                if st.button("Fertilize Plant"):
                    update_plant(
                        selected_plant,
                        "last_fertilized",
                        datetime.now().date(),
                        st.session_state.username,
                    )
                    st.success("Fertilizing recorded!")

                new_notes = st.text_area("Update Notes", plant_data["notes"])
                if st.button("Update Notes"):
                    update_plant(
                        selected_plant, "notes", new_notes, st.session_state.username
                    )
                    st.success("Notes updated!")

            with col2:
                uploaded_file = st.file_uploader("Upload Plant Photo")
                if uploaded_file:
                    img = Image.open(uploaded_file)
                    img_bytes = io.BytesIO()
                    img.save(img_bytes, format="PNG")
                    add_photo(
                        selected_plant, img_bytes.getvalue(), st.session_state.username
                    )
                    st.success("Photo uploaded!")

                photos = get_photos(selected_plant, st.session_state.username)

            if photos:
                st.write("Growth Timeline:")
                for i, (rowid, photo, date, photo_notes) in enumerate(photos):
                    col3, col4 = st.columns([3, 1])
                    with col3:
                        img = Image.open(io.BytesIO(photo))
                        st.image(img, caption=f"Date: {date}", width=300)

                        current_notes = st.text_area(
                            "Photo Notes",
                            value=photo_notes,
                            key=f"{selected_plant}_{rowid}_{i}",
                        )

                        if st.button(
                            "Save Photo Note", key=f"save_{selected_plant}_{rowid}_{i}"
                        ):
                            update_photo_notes(
                                selected_plant,
                                date,
                                current_notes,
                                st.session_state.username,
                            )
                            st.success("Note saved!")
                            st.rerun()

                    with col4:
                        if st.button(
                            "Delete Photo", key=f"delete_{selected_plant}_{rowid}_{i}"
                        ):
                            delete_photo(
                                selected_plant, date, st.session_state.username
                            )
                            st.success("Photo deleted!")
                            st.rerun()

            days_since_water = (
                datetime.now().date()
                - pd.to_datetime(plant_data["last_watered"]).date()
            ).days
            days_since_fert = (
                datetime.now().date()
                - pd.to_datetime(plant_data["last_fertilized"]).date()
            ).days

            st.markdown(
                f"""
            **Plant Details:**
            - Species: {plant_data['species']}
            - Days since last watering: {days_since_water}
            - Days since last fertilizing: {days_since_fert}
            """
            )
