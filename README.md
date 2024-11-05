# Linode Firewall Autoupdater

The Linode firewall uses an allowlist to prevent unwanted traffic on my server. This script is to update the allowlist in the Linode firewall automatically and runs its job every 5 minutes in the Docker container.

## Setup

#### Running Locally

1. Download repo
    - `git clone https://github.com/littlehoushontheprairie/linode-firewall-autoupdater.git`
    - `git checkout develop`
    - `git pull`
    - `cd linode-firewall-autoupdater`
2. Export environment variables
3. Run
    - `python3 linode_firewall_autoupdater.py`

#### Building and Running as Container from Source

1. Download repo
    - `git checkout develop`
    - `git pull`
    - `cd linode-firewall-autoupdater`
2. Export environment variables
3. run docker-compose
    - `docker-compose up --build -d`

#### Running Container from GitHub Docker Registry (using Terminal)

1. Download `latest` container
    - `docker pull ghcr.io/littlehoushontheprairie/linode-firewall-autoupdater:latest`
2. Run container
    - ```
      docker run --restart=always -d --network host \
      --name linode_firewall_autoupdater \
      -e TZ="America/Los_Angeles" \
      -e LINODE_TOKEN="8f5cd6729h0v5d247vc190ddcs4l2b"
      -e LINODE_FIREWALL_IDS="12345"
      -e LINODE_LABEL_NAME="home"
      -e FROM_EMAIL="from@example.com" \
      -e TO_EMAIL="to@example.com" \
      -e SMTP_HOST="smtp.example.com" \
      -e SMTP_USER="laura@example.com" \
      -e SMTP_PASSWORD="8f5cd6729h0v5d247vc190ddcs4l2a" \
      -e PROXY_URL="proxy.example.com" \
      ghcr.io/littlehoushontheprairie/linode-firewall-autoupdater:latest
      ```

#### Running Container from GitHub Docker Registry (using docker-compose)

1. Create `docker-compose.yml` file
2. Add content.

    - ```
      version: "3.5"

      services:
        linode_firewall_autoupdater:
          container_name: linode_firewall_autoupdater
          image: ghcr.io/littlehoushontheprairie/linode-firewall-autoupdater:latest
          restart: always
          network_mode: host
          environment:
            TZ: America/Los_Angeles
            LINODE_TOKEN: "${LINODE_TOKEN}"
            LINODE_FIREWALL_IDS: "${LINODE_FIREWALL_IDS}"
            LINODE_LABEL_NAME: "${LINODE_LABEL_NAME}"
            FROM_EMAIL: "${FROM_EMAIL}"
            TO_EMAIL: "${TO_EMAIL}"
            SMTP_HOST: "${SMTP_HOST}"
            SMTP_USER: "${SMTP_USER}"
            SMTP_PASSWORD: "${SMTP_PASSWORD}"
            PROXY_URL: "${PROXY_URL}"
      ```

3. Export environment variables
4. Run `docker-compose up -d`

## Email Templates

The script reads in email templates everytime it is ran. You can customize the templates located in the _templates_ folder. They are read in as HTML files and are injected at runtime with the information.

### Structure

-   error.html - Error Template
-   index.html - Main Template

## Environment Variables

| Variable            | Required | Default                     | Example                        | Needed by                     |
| ------------------- | -------- | --------------------------- | ------------------------------ | ----------------------------- |
| FROM_NAME           | false    | Linode Firewall Autoupdater | Linode Firewall Autoupdater    | SMTP Server (send email from) |
| FROM_EMAIL          | true     | ---                         | from@example.com               | SMTP Server (send email from) |
| TO_NAME             | false    |                             | Laura                          | SMTP Server (send email to)   |
| TO_EMAIL            | true     | ---                         | to@example.com                 | SMTP Server (send email to)   |
| PROXY_URL           | true     | ---                         | nginx.example.com              | Template                      |
| LINODE_TOKEN        | true     | ---                         | 8f5cd6729h0v5d247vc190ddcs4l2a | Linode API                    |
| LINODE_FIREWALL_IDS | true     | ---                         | 123,456                        | Linode API                    |
| LINODE_LABEL_NAME   | true     | ---                         | home                           | Linode API                    |
| SMTP_HOST           | true     | ---                         | smtp.example.com               | SMTP Server                   |
| SMTP_PORT           | false    | 465                         | 465                            | SMTP Server                   |
| SMTP_USER           | true     | ---                         | laura@example.com              | SMTP Server                   |
| SMTP_PASSWORD       | true     | ---                         | 8f5cd6729h0v5d247vc190ddcs4l2a | SMTP Server                   |

**NOTE:** For security purposes, it is strong recommended that you use a generated API passwords.
