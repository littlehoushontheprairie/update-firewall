class EmailTemplates:
    def __init__(self):
        file = open("templates/index.html", "r")
        self.basic_template: str = file.read()

        file = open("templates/error.html", "r")
        self.error_template: str = file.read()

    def generate_basic_template(self, entries: dict) -> str:
        return self.basic_template.format(to_name=entries["to_name"], inbound_rule_changes=entries["inbound_rule_changes"], proxy_url=entries["proxy_url"])

    def generate_error_template(self, entries: dict) -> str:
        return self.error_template.format(to_name=entries["to_name"], status_code=entries["status_code"])

    def generate_inbound_rule_changes(self, inbound_rule_changes: dict) -> str:
        html = "<ul>"

        for firewall_id in inbound_rule_changes.keys():
            inbound_rule_change = inbound_rule_changes[firewall_id]
            html = f"{html}<li>Firewall {inbound_rule_change.firewall_name} has updated the ip"
            html = f"{html} from {inbound_rule_change.from_ip} to {inbound_rule_change.to_ip}.</li>"

        return f"{html}</ul>"
