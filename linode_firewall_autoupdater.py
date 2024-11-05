import os
import requests
import logging
import schedule
import time
from dataclasses import dataclass
from smtp import SMTP, Email, SMTPOptions
from email_templates import EmailTemplates

LINODE_TOKEN: str = os.environ.get("LINODE_TOKEN")
LINODE_FIREWALL_IDS: list = os.environ.get(
    "LINODE_FIREWALL_IDS", "").split(",")
LINODE_LABEL_NAME: str = os.environ.get("LINODE_LABEL_NAME")
LINODE_HEADERS: dict = {"Authorization": "Bearer " +
                        LINODE_TOKEN if LINODE_TOKEN is not None else ""}

FROM_NAME: str = os.environ.get("FROM_NAME", "Linode Firewall Autoupdater")
FROM_EMAIL: str = os.environ.get("FROM_EMAIL")
TO_NAME: str = os.environ.get("TO_NAME", "")
TO_EMAIL: str = os.environ.get("TO_EMAIL")

SMTP_HOST: str = os.environ.get("SMTP_HOST")
SMTP_PORT: int = int(os.environ.get("SMTP_PORT", 465))
SMTP_USER: str = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

PROXY_URL: str = os.environ.get("PROXY_URL")

IPIFY_API_URL: str = "https://api.ipify.org?format=json"


assert (LINODE_TOKEN is None, "LINODE_TOKEN is required.")
assert (len(LINODE_FIREWALL_IDS) == 1 and len(
    LINODE_FIREWALL_IDS[0]), "LINODE_FIREWALL_IDS is required.")
assert (LINODE_LABEL_NAME is None, "LINODE_LABEL_NAME is required.")
assert (FROM_EMAIL is None, "FROM_EMAIL is required.")
assert (TO_EMAIL is None, "TO_EMAIL is required.")
assert (SMTP_HOST is None, "SMTP_HOST is required.")
assert (SMTP_USER is None, "SMTP_USER is required.")
assert (SMTP_PASSWORD is None, "SMTP_PASSWORD is required.")
assert (PROXY_URL is None, "PROXY_URL is required.")


# Enable logging
logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s",
                    level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")


@dataclass
class InboundRuleChange:
    firewall_id: str
    firewall_name: str
    from_ip: str
    to_ip: str


def job():
    logging.info("Running job...")

    smtp_options: SMTPOptions = SMTPOptions(
        host=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASSWORD)
    smtp: SMTP = SMTP(smtp_options=smtp_options)
    email_templates: EmailTemplates = EmailTemplates()

    inbound_rule_changes: dict = {}

    # Ipify GET
    ip_response = requests.get(IPIFY_API_URL)

    if ip_response.status_code == 200:
        ip = ip_response.json()["ip"]

        # Linode API
        for firewall_id in LINODE_FIREWALL_IDS:
            firewall_response = requests.get(
                f"https://api.linode.com/v4/networking/firewalls/{firewall_id}", headers=LINODE_HEADERS)

            if firewall_response.status_code == 200:
                firewall: dict = firewall_response.json()
                firewall_name: str = firewall["label"]
                firewall_rules: dict = firewall["rules"]
                inbound_rules: list = firewall_rules["inbound"]

                for inbound_rule in inbound_rules:
                    if LINODE_LABEL_NAME + "-" in inbound_rule["label"] and ip not in inbound_rule["addresses"]["ipv4"][0]:
                        if inbound_rule_changes.get(firewall_id) is None:
                            inbound_rule_changes[firewall_id] = InboundRuleChange(
                                firewall_id=firewall_id,
                                firewall_name=firewall_name,
                                from_ip=inbound_rule["addresses"]["ipv4"][0].split(
                                    "/")[0],
                                to_ip=ip
                            )

                        old_ip_address: str = inbound_rule["addresses"]["ipv4"][0].split(
                            "/")[0]
                        inbound_rule["addresses"]["ipv4"][0] = ip + "/32"

                        logging.info(
                            f"Updating Linode firewall, {firewall_name}, with IP from {old_ip_address} to {ip} for label, {LINODE_LABEL_NAME}")

                        updated_firewall_response = requests.put(
                            f"https://api.linode.com/v4/networking/firewalls/{firewall_id}/rules", headers=LINODE_HEADERS, json=firewall_rules)
                        if updated_firewall_response.status_code == 200:
                            logging.info(
                                f"Firewall,{firewall_id} {firewall_name}, has been updated.")
                        elif updated_firewall_response.status_code in [401, 403]:
                            logging.error(
                                f"api.linode.com (update firewall rules) has an authentication issue. Status: {str(ip_response.status_code)}")
                        elif updated_firewall_response.status_code in [500, 502, 503, 504]:
                            logging.error(
                                f"api.linode.com (update firewall rules) has failed due to a server side issue has occurred. Status: {str(ip_response.status_code)}")

            elif firewall_response.status_code in [401, 403]:
                logging.error(
                    f"api.linode.com (get firewall rules) has an authentication issue. Status: {str(ip_response.status_code)}")
            elif firewall_response.status_code in [500, 502, 503, 504]:
                logging.error(
                    f"api.linode.com (get firewall rules) has failed due to a server side issue has occurred. Status: {str(ip_response.status_code)}")

        if len(inbound_rule_changes.keys()) > 0:
            logging.info("Sending email...")
            email: Email = Email(from_name=FROM_NAME, from_email=FROM_EMAIL, to_name=TO_NAME, to_email=TO_EMAIL,
                                 subject="Firewall has been updated",
                                 body=email_templates.generate_basic_template(
                                     dict(to_name=TO_NAME, inbound_rule_changes=email_templates.generate_inbound_rule_changes(inbound_rule_changes=inbound_rule_changes), proxy_url=PROXY_URL)))
            smtp.send_email(email=email)
            logging.info(
                f"Job finished. Updated {len(inbound_rule_changes)} firewalls.")
        else:
            logging.info("Job finished. No update.")

    elif ip_response.status_code in [401, 403, 429, 500, 502, 503, 504]:
        logging.error(
            f"api.ipify.org has returned an unexpected status. Status: {str(ip_response.status_code)}")


schedule.every(5).minutes.do(job)

while True:
    schedule.run_pending()
    time.sleep(1)
