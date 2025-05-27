import boto3
from jinja2 import Environment, FileSystemLoader


def get_all_lb_attributes():
    compiled_load_balancers = {
        "load_balancers": []
    }
    # Create a client for ELBv2 (Application and Network Load Balancers)
    elbv2 = boto3.client("elbv2")
    # Retrieve all load balancers
    response = elbv2.describe_load_balancers()
    load_balancers = response.get("LoadBalancers")

    # Iterate through all the load balancers within the account
    for lb in load_balancers:
        lb_arn = lb["LoadBalancerArn"]
        formatted_lb_attributes = {"arn": lb_arn, "listeners": []}

        lb_listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)

        # For each LB, get the listener information
        for listener in lb_listeners.get("Listeners"):
            print(listener)
            lb_listener_arn = listener["ListenerArn"]
            formatted_lb_listener = {
                "arn": lb_listener_arn,
                "port": listener.get("Port"),
                "protocol": listener.get("Protocol"),
                "ssl_policy": str(listener.get("SslPolicy")),
                "rules": [],
                "certificates": []
            }

            # Get listener rules
            lb_listener_rules = elbv2.describe_rules(ListenerArn=lb_listener_arn)
            for rule in lb_listener_rules.get("Rules"):
                formatted_lb_listener_rule = {
                    "arn": rule.get("RuleArn"),
                    "actions": [
                        {
                            "type": action.get("Type"),
                            "TargetGroupArn": action.get("TargetGroupArn"),
                            "Order": str(action.get("Order"))
                        } for action in rule.get("Actions")]
                }
                formatted_lb_listener.get("rules").append(formatted_lb_listener_rule)

            # Get listener certs
            lb_listener_certs = elbv2.describe_listener_certificates(ListenerArn=lb_listener_arn)
            for lb_listener_cert in lb_listener_certs.get("Certificates", []):
                formatted_lb_listener_cert = {"CertificateArn": lb_listener_cert.get("CertificateArn")}

                if formatted_lb_listener_cert:
                    formatted_lb_listener["certificates"].append(formatted_lb_listener_cert)

            formatted_lb_attributes["listeners"].append(formatted_lb_listener)
        compiled_load_balancers["load_balancers"].append(formatted_lb_attributes)

    return compiled_load_balancers


def render_template(lb_info):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('tfvars.template')
    output = template.render(lb_info)
    print(output)


lb_info = get_all_lb_attributes()
render_template(lb_info)
