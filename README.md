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
load_balancer_config = {
    arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:loadbalancer/net/likzv/99b9c61d4191f150"
    listeners = [
        {
            arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener/net/likzv/99b9c61d4191f150/185ad7398dec6f65",
            port = "8200",
            protocol = "TCP"
            rules = [
                arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener-rule/net/likzv/99b9c61d4191f150/185ad7398dec6f65/197ebee75dc12de8"
                target_group = {
                    target_group_arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:targetgroup/likzv-vault/1ee5660685f7cb58",
                    type = "forward",
                    order = "1"
                }
            ]
            certificate_arns = [
            ]
        }, 
        {
            arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener/net/likzv/99b9c61d4191f150/1d5fdd3d18f06f78",
            port = "443",
            protocol = "TLS"
            rules = [
                arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener-rule/net/likzv/99b9c61d4191f150/1d5fdd3d18f06f78/818caaadc3cfcf75"
                target_group = {
                    target_group_arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:targetgroup/likzv-vault/1ee5660685f7cb58",
                    type = "forward",
                    order = "None"
                }
            ]
            certificate_arns = [
                "arn:aws:acm:ap-southeast-1:058264549112:certificate/2d2f0cb1-c08d-4e9e-9de2-a2aef02cd665", 
                "arn:aws:acm:ap-southeast-1:058264549112:certificate/a7134534-82d5-4fba-920a-76dd920178fa"
            ]
        }, 
        {
            arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener/net/likzv/99b9c61d4191f150/f5744a6ae66847aa",
            port = "5696",
            protocol = "TCP"
            rules = [
                arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:listener-rule/net/likzv/99b9c61d4191f150/f5744a6ae66847aa/299d68adf96053c7"
                target_group = {
                    target_group_arn = "arn:aws:elasticloadbalancing:ap-southeast-1:058264549112:targetgroup/likzv-vault-kmip/e379c7749487ec8e",
                    type = "forward",
                    order = "None"
                }
            ]
            certificate_arns = [
            ]
        }
    ]
}
```