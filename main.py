import boto3
from jinja2 import Environment, FileSystemLoader


def get_attribute_value(lb_attributes, key, return_if_none=None):
    value = next((d["Value"] for d in lb_attributes.get("Attributes") if d["Key"] == key), None)
    return value if value else return_if_none


def write_file(file_name, content):
    f = open(file_name, "w")
    f.write(str(content))
    f.close()


def get_all_lb_attributes():
    response_audit_dump = []
    # Create a client for ELBv2 (Application and Network Load Balancers)
    elbv2 = boto3.client("elbv2")
    # Retrieve all load balancers
    response = elbv2.describe_load_balancers()
    load_balancers = response.get("LoadBalancers")
    # Iterate through all the load balancers within the account
    for lb in load_balancers:
        lb_arn = lb["LoadBalancerArn"]
        lb_attributes = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
        # Get LB tags
        lb_tags = elbv2.describe_tags(ResourceArns=[lb_arn])

        audit_dump_lb_attributes = lb
        audit_dump_lb_attributes["Attributes"] = lb_attributes
        audit_dump_lb_attributes["Tags"] = lb_tags
        audit_dump_lb_attributes["Listeners"] = []
        audit_dump_lb_attributes["TargetGroups"] = []

        # For each LB, get the listener information
        lb_listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)
        for listener in lb_listeners.get("Listeners"):
            lb_listener_arn = listener["ListenerArn"]
            # Get listener rules
            lb_listener_rules = elbv2.describe_rules(ListenerArn=lb_listener_arn)
            # Get listener certs
            lb_listener_certs = elbv2.describe_listener_certificates(ListenerArn=lb_listener_arn)

            audit_dump_lb_attributes["Listeners"].append({
                "Attributes": listener,
                "Rules": lb_listener_rules,
                "Certificates": lb_listener_certs
            })

        # For each LB, get the target groups
        lb_target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
        # audit_dump_lb_attributes["TargetGroups"] = lb_target_groups
        # print(lb_target_groups)
        # target_groups_attributes = lb_target_groups
        for tg in lb_target_groups.get("TargetGroups"):
            tg_arn = tg.get("TargetGroupArn")
            tg_attributes = elbv2.describe_target_group_attributes(TargetGroupArn=tg_arn)
            # target_groups_attributes["Attributes"] = tg_attributes
            audit_dump_lb_attributes["TargetGroups"].append(
                {
                    "TargetGroup": tg,
                    "Attributes": tg_attributes
                }
            )
            # audit_dump_lb_attributes["TargetGroups"].append(target_groups_attributes)

        response_audit_dump.append(audit_dump_lb_attributes)
    write_file("audit.json", str(response_audit_dump))
    return response_audit_dump


def format_lb_attributes(load_balancers_info):
    compiled_load_balancers = {
        "load_balancers": []
    }

    # Iterate through all the load balancers within the account
    for lb in load_balancers_info:
        lb_arn = lb["LoadBalancerArn"]
        is_internal = True if lb.get("Scheme") == "internet-facing" else False
        is_alb = True if lb.get("Type") == "application" else False
        # Get LB tags
        lb_tags = lb.get("Tags")
        # Get LB attributes
        lb_attributes = lb.get("Attributes")
        # print(lb_attributes.get("Attributes"))

        formatted_lb_attributes = {
            "arn": lb_arn,
            "lb_name": lb.get("LoadBalancerName"),
            "internal": is_internal,
            "load_balancer_type": lb.get("Type"),
            "vpc_id": lb.get("VpcId"),
            "subnets": [az.get("SubnetId") for az in lb.get("AvailabilityZones")],
            "security_groups_ids": lb.get("SecurityGroups", []),
            "ip_address_type": lb.get("IpAddressType"),
            "enforce_security_group_inbound_rules_on_private_link_traffic": lb.get("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic", "on"),
            # Only applicable to NLB but seems like sample structure has this attribute so we cater for it
            "customer_owned_ipv4_pool": lb.get("CustomerOwnedIpv4Pool") if lb.get("CustomerOwnedIpv4Pool") else None,
            "enable_deletion_protection": get_attribute_value(lb_attributes, "deletion_protection.enabled", "false"),
            "enable_cross_zone_load_balancing": get_attribute_value(lb_attributes, "load_balancing.cross_zone.enabled", "true" if is_alb else "false"),
            "client_keep_alive": get_attribute_value(lb_attributes, "client_keep_alive.seconds", 3600),
            "desync_mitigation_mode": get_attribute_value(lb_attributes, "routing.http.desync_mitigation_mode", "defensive"),
            "dns_record_client_routing_policy": get_attribute_value(lb_attributes, "dns_record.client_routing_policy", "any_availability_zone"),
            "drop_invalid_header_fields": get_attribute_value(lb_attributes, "routing.http.drop_invalid_header_fields.enabled", "false"),
            "enable_http2": get_attribute_value(lb_attributes, "routing.http2.enabled", "true"),
            "enable_tls_version_and_cipher_suite_headers": get_attribute_value(lb_attributes, "routing.http.x_amzn_tls_version_and_cipher_suite.enabled", "false"),
            "enable_waf_fail_open": get_attribute_value(lb_attributes, "waf.fail_open.enabled", "false"),
            "enable_xff_client_port": get_attribute_value(lb_attributes, "routing.http.xff_client_port.enabled", "false"),
            "xff_header_processing_mode": get_attribute_value(lb_attributes, "routing.http.xff_header_processing.mode", "false"),
            "enable_zonal_shift": get_attribute_value(lb_attributes, "zonal_shift.config.enabled", "false"),
            "idle_timeout": get_attribute_value(lb_attributes, "idle_timeout.timeout_seconds", 60),
            "preserve_host_header": get_attribute_value(lb_attributes, "routing.http.preserve_host_header.enabled", "false"),
            "listeners": [],
            "target_groups": [],
            "access_logs": [{
                "bucket": get_attribute_value(lb_attributes, "access_logs.s3.bucket", ""),
                "enabled": get_attribute_value(lb_attributes, "access_logs.s3.enabled", "false"),
                "prefix": get_attribute_value(lb_attributes, "access_logs.s3.prefix", "")
            }],
            "connection_logs": [{
                "bucket": get_attribute_value(lb_attributes, "connection_logs.s3.bucket", ""),
                "enabled": get_attribute_value(lb_attributes, "connection_logs.s3.enabled", "false"),
                "prefix": get_attribute_value(lb_attributes, "connection_logs.s3.prefix", "")
            }],
            "subnet_mapping": [
                {
                    "subnet_id": az.get("SubnetId"),
                    "allocation_id": az.get("LoadBalancerAddresses")[0].get("AllocationId") if az.get("LoadBalancerAddresses") else "null",
                    "ipv6_address": az.get("LoadBalancerAddresses")[0].get("IPv6Address") if az.get("LoadBalancerAddresses") else "null",
                    "private_ipv4_address": az.get("LoadBalancerAddresses")[0].get("PrivateIPv4Address") if az.get("LoadBalancerAddresses") else "null"
                } for az in lb.get("AvailabilityZones")
            ],
            "tags": [{"key": tag.get("Key"), "value": tag.get("Value")} for tag in lb_tags.get("TagDescriptions", [{"Tags": {}}])[0].get("Tags", [])]
        }

        lb_listeners = lb.get("Listeners")
        # For each LB, get the listener information
        for listener_info in lb_listeners:
            listener = listener_info.get("Attributes")
            formatted_listener_config = {
                "port": listener.get("Port"),
                "protocol": listener.get("Protocol"),
            }

            # Get listener rules
            weighted_listener_rules = []
            default_action_rule = {}

            for rule in listener_info.get("Rules").get("Rules"):
                for action in rule.get("Actions"):
                    if action.get("ForwardConfig"):
                        weighted_listener_rules.append(
                            {
                                "target_group_key": action.get("TargetGroupArn"),
                                "target_groups": [{
                                    "target_group_key": tg.get("TargetGroupArn"),
                                    "weight": tg.get("Weight")
                                } for tg in action.get("ForwardConfig").get("TargetGroups")]
                            }
                        )
                    if action.get("FixedResponseConfig"):
                        default_action_rule = {
                            action.get("Type"): {
                                "content_type": action.get("FixedResponseConfig").get("ContentType"),
                                "message_body": action.get("FixedResponseConfig").get("MessageBody"),
                                "status_code": action.get("FixedResponseConfig").get("StatusCode")
                            }
                        }

            if weighted_listener_rules:
                formatted_listener_config["weighted_forward"] = weighted_listener_rules
            if default_action_rule:
                formatted_listener_config["default_action"] = default_action_rule

            # Get listener certs
            certificates = listener_info.get("Certificates").get("Certificates")
            certificate_arn = "None"
            additional_certificate_arns = []

            if certificates:
                certificate_arn = next((cert["CertificateArn"] for cert in certificates if cert["IsDefault"]))  # Default certificate
                additional_certificate_arns = [cert["CertificateArn"] for cert in certificates if not cert["IsDefault"]]  # Any additional certificates attached to the listener

            formatted_listener_config["certificate_arn"] = certificate_arn
            formatted_listener_config["additional_certificate_arns"] = additional_certificate_arns

            formatted_lb_listener = {
                f"listener-{listener.get('Port')}": formatted_listener_config
            }

            formatted_lb_attributes["listeners"].append(formatted_lb_listener)

        lb_tgs = lb.get("TargetGroups")
        for tg_info in lb_tgs:
            tg = tg_info.get("TargetGroup")
            tg_attributes = tg_info.get("Attributes")
            formatted_lb_attributes["target_groups"].append({
                "name": tg.get("TargetGroupName"),
                "port": tg.get("Protocol"),
                "protocol": tg.get("Port"),
                "vpc_id": tg.get("VpcId"),
                "health_check": {
                    "enabled": str(tg.get("HealthCheckEnabled")).lower(),
                    "healthy_threshold": tg.get("HealthyThresholdCount"),
                    "interval": tg.get("HealthCheckIntervalSeconds"),
                    "path": tg.get("HealthCheckPath"),
                    "protocol": tg.get("HealthCheckProtocol"),
                    "timeout": tg.get("HealthCheckTimeoutSeconds"),
                    "unhealthy_threshold": tg.get("UnhealthyThresholdCount"),
                },
                "stickiness": {
                    "enabled": get_attribute_value(tg_attributes, "stickiness.enabled", "false"),
                    "type": get_attribute_value(tg_attributes, "stickiness.type", "source_ip"),
                },
                "target_type": tg.get("TargetType")
            })
        compiled_load_balancers["load_balancers"].append(formatted_lb_attributes)

    write_file("render.json", str(compiled_load_balancers))
    return compiled_load_balancers


def render_template(lb_info):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('tfvars.template')
    output = template.render(lb_info)
    print(output)
    return output


raw_info = get_all_lb_attributes()
lb_info = format_lb_attributes(raw_info)
write_file("example.tfvars", render_template(lb_info))
