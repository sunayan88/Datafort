# Datafort Installation Guide (Kali Linux)

## Step 1: Clone the Repository

Clone the master branch:

git clone https://github.com/sunayan88/Datafort.git

You must have these installed:

- docker.io
- docker-compose


## Step 2: Set the DISPLAY Variable

Kali Linux has a native X server running on :0 by default.

Run:

export DISPLAY=:0


## Step 3: Build the Docker Container

Run:

docker-compose up --build


## Step 4: Initialize CA and Admin User (One-Time Setup)

⚠️ This must be done while the tool is running.

Open another terminal and run:

docker exec -it datafort-app bash

Then run:

python scripts/init_ca_and_admin.py

You will be prompted to create the admin user.

After that, generate system keys:

python scripts/generate_system_keys.py


## Installation Complete

Enjoy! The tool is properly installed and working.
