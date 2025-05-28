# Setup Python Environment

1. Create and Python venv
    ```shell
    python3 -m venv venv
    ```
2. Activate venv
    ```shell
   source venv/bin/activate
    ```
3. Install requirements 
   ```shell
   pip install -r requirements.txt
   ```

# Setup AWS Credentials
```shell
export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
export AWS_SESSION_TOKEN=YOUR_SESSION_TOKEN  # If using temporary credentials
export AWS_DEFAULT_REGION=REGION
```

# Example output
```shell
lb_config = {
  "likzv" = {
    lb_name = "likzv"
    internal = True
    load_balancer_type = "network"
    subnet = ['subnet-050239ff37c785c2a']
    tags = {
      Project-Code = "CK"
      Team = "SEC"
      Name = "test"
    }
    deletion_protection = "false"
    enable_cross_zone_load_balancing = "false"
    vpc_id = "vpc-0958771d93cc3cc6c"
    security_groups_ids = []

    ip_address_type = "ipv4"
    load_balancer_type = "network"
    client_keep_alive = "3600"
    customer_owned_ipv4_pool = "None"
    desync_mitigation_mode = "defensive"
    dns_record_client_routing_policy = "any_availability_zone"
    drop_invalid_header_fields = "False"
    enable_cross_zone_load_balancing = "false"
    enable_deletion_protection = ""
    enable_http2 = "True"
    enable_tls_version_and_cipher_suite_headers = "False"
    enable_waf_fail_open = "False"
    enable_xff_client_port = "False"
    xff_header_processing_mode = "False"
    enable_zonal_shift = "false"
    enforce_security_group_inbound_rules_on_private_link_traffic = "on"
    idle_timeout = "60"
    preserve_host_header = "False"

    listeners = {
      listener-8200 = {
        port = "8200"
        protocol = "TCP"
        certificate_arn = ""
        additional_certificate_arns = []
        weighted_forward = [
          {
            target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault/1ee5660685f7cb58"
            target_groups = [
              {
                target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault/1ee5660685f7cb58"
                weight = None
              }
            ]
          }
        ]
      }
      listener-443 = {
        port = "443"
        protocol = "TLS"
        certificate_arn = ""
        additional_certificate_arns = ['arn:aws:acm:ap-southeast-1:123456789012:certificate/2fec407d-821f-4228-8c40-716a77b437f6', 'arn:aws:acm:ap-southeast-1:123456789012:certificate/2d2f0cb1-c08d-4e9e-9de2-a2aef02cd665', 'arn:aws:acm:ap-southeast-1:123456789012:certificate/a7134534-82d5-4fba-920a-76dd920178fa']
        weighted_forward = [
          {
            target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault/1ee5660685f7cb58"
            target_groups = [
              {
                target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault/1ee5660685f7cb58"
                weight = None
              }
            ]
          }
        ]
      }
      listener-5696 = {
        port = "5696"
        protocol = "TCP"
        certificate_arn = ""
        additional_certificate_arns = []
        weighted_forward = [
          {
            target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault-kmip/e379c7749487ec8e"
            target_groups = [
              {
                target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/likzv-vault-kmip/e379c7749487ec8e"
                weight = None
              }
            ]
          }
        ]
      }
    }
  }
  "test" = {
    lb_name = "test"
    internal = False
    load_balancer_type = "application"
    subnet = ['subnet-0bd0945130fb0ce5f', 'subnet-0d8007e17249aa3cc']
    tags = {
    }
    deletion_protection = "false"
    enable_cross_zone_load_balancing = "true"
    vpc_id = "vpc-0958771d93cc3cc6c"
    security_groups_ids = ['sg-03b051e17aa170fcc']

    ip_address_type = "ipv4"
    load_balancer_type = "application"
    client_keep_alive = "3600"
    customer_owned_ipv4_pool = "None"
    desync_mitigation_mode = "defensive"
    dns_record_client_routing_policy = "any_availability_zone"
    drop_invalid_header_fields = "false"
    enable_cross_zone_load_balancing = "true"
    enable_deletion_protection = ""
    enable_http2 = "true"
    enable_tls_version_and_cipher_suite_headers = "false"
    enable_waf_fail_open = "false"
    enable_xff_client_port = "false"
    xff_header_processing_mode = "append"
    enable_zonal_shift = "false"
    enforce_security_group_inbound_rules_on_private_link_traffic = "on"
    idle_timeout = "60"
    preserve_host_header = "false"

    listeners = {
      listener-81 = {
        port = "81"
        protocol = "HTTP"
        certificate_arn = ""
        additional_certificate_arns = []
        default_action = {
          fixed-response = {
            content_type = "text/plain"
            message_body = "test"
            status_code = "503"
          }
        }
      }
      listener-80 = {
        port = "80"
        protocol = "HTTP"
        certificate_arn = ""
        additional_certificate_arns = []
        weighted_forward = [
          {
            target_group_key = "None"
            target_groups = [
              {
                target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/test3/2b6309c644b07bc4"
                weight = 1
              }, 
              {
                target_group_key = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/test/fbb09289b209396d"
                weight = 1
              }
            ]
          }
        ]
      }
    }
  }
}
```