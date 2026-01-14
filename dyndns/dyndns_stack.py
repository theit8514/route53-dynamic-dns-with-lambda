import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_lambda as lambda_
import aws_cdk.aws_dynamodb as dynamodb
import aws_cdk.aws_iam as iam
import aws_cdk.aws_apigateway as apigateway
import aws_cdk.aws_certificatemanager as certificatemanager
import aws_cdk.aws_route53 as route53
import aws_cdk.aws_route53_targets as route53_targets
from cdk_nag import AwsSolutionsChecks, NagSuppressions, NagPackSuppression

class DyndnsStack(cdk.Stack):

    def __init__(self, scope: cdk.App, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
     
        
        # Create DynamoDB table with configurable capacity
        # Get billing mode from context (default: on-demand)
        billing_mode_str = self.node.try_get_context("dynamodb_billing_mode") or "on-demand"
        billing_mode = dynamodb.BillingMode.PAY_PER_REQUEST if billing_mode_str.lower() == "on-demand" else dynamodb.BillingMode.PROVISIONED
        
        # Build table props
        table_props = {
            "partition_key": dynamodb.Attribute(name="hostname", type=dynamodb.AttributeType.STRING),
            "sort_key": dynamodb.Attribute(name="record_type", type=dynamodb.AttributeType.STRING),
            "removal_policy": cdk.RemovalPolicy.DESTROY,
            "point_in_time_recovery": True,
            "billing_mode": billing_mode
        }
        
        # If using provisioned capacity, set read and write capacity units
        if billing_mode == dynamodb.BillingMode.PROVISIONED:
            read_capacity = self.node.try_get_context("dynamodb_read_capacity")
            write_capacity = self.node.try_get_context("dynamodb_write_capacity")
            
            # Default to 5 units if not specified
            table_props["read_capacity"] = read_capacity if read_capacity is not None else 5
            table_props["write_capacity"] = write_capacity if write_capacity is not None else 5
        
        table = dynamodb.Table(self, "dyndns_db", **table_props)
        
        #Create Lambda role
        fn_role = iam.Role(self, "dyndns_fn_role",
            assumed_by = iam.ServicePrincipal("lambda.amazonaws.com"),
            description = "DynamicDNS Lambda role",
            inline_policies = {
                'r53': iam.PolicyDocument(
                    statements = [
                        iam.PolicyStatement(
                            effect = iam.Effect.ALLOW,
                            resources = [
                                "*"
                            ],
                          actions = [
                                "route53:ChangeResourceRecordSets","route53:ListResourceRecordSets"
                            ]
                        )
                    ],
                ),
                'cw': iam.PolicyDocument(
                    statements = [
                        iam.PolicyStatement(
                            effect = iam.Effect.ALLOW,
                            resources = [
                                "*"
                            ],
                          actions = [
                                "logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"
                            ]
                        )
                    ],
                )
            }
        ) 


        # Get input mode from context (default: body)
        input_mode = self.node.try_get_context("lambda_input_mode") or "body"
        
        # Determine HTTP method based on input mode
        # If input_mode is "body", use POST; otherwise use GET
        http_method = "POST" if input_mode.lower() == "body" else "GET"
        
        fn = lambda_.Function(self, "dyndns_fn",
            runtime=lambda_.Runtime.PYTHON_3_14,
            architecture=lambda_.Architecture.ARM_64,
            handler="index.lambda_handler",
            code=lambda_.Code.from_asset("lambda"),
            role=fn_role,
            timeout=cdk.Duration.seconds(8),
            #Provide DynamoDB table name and input mode as environment variables
            environment={
                "ddns_config_table": table.table_name,
                "input_mode": input_mode
            }
        )            

        # Optional: Get custom domain configuration
        custom_domain_name = self.node.try_get_context("custom_domain_name")
        certificate_arn = self.node.try_get_context("certificate_arn")
        route53_zone_name = self.node.try_get_context("route53_zone_name")  # Required for auto DNS setup
        route53_zone_id = self.node.try_get_context("route53_zone_id")  # Required for auto DNS setup
        
        # Create custom domain separately if provided (so we can access its properties)
        custom_domain = None
        certificate = None
        if custom_domain_name and certificate_arn:
            certificate = certificatemanager.Certificate.from_certificate_arn(
                self, "CustomDomainCertificate",
                certificate_arn=certificate_arn
            )
            custom_domain = apigateway.DomainName(self, "CustomDomain",
                domain_name=custom_domain_name,
                certificate=certificate
            )
        
        # Build REST API properties
        # Include both GET and POST in CORS to support both modes
        api_props = {
            "rest_api_name": "Dynamic DNS API",
            "description": "API Gateway for Dynamic DNS Lambda function",
            "default_cors_preflight_options": apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=[http_method, "OPTIONS"],
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"],
                allow_credentials=False
            ),
            "endpoint_configuration": apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            )
        }
        
        # Create REST API Gateway
        # REST API supports native API key authentication
        # Note: CORS is handled by the Lambda function's response headers
        api = apigateway.RestApi(self, "dyndns_api", **api_props)
        
        # Create base path mapping if custom domain is configured
        if custom_domain:
            apigateway.BasePathMapping(self, "BasePathMapping",
                domain_name=custom_domain,
                rest_api=api,
                base_path=""
            )

        # Create Lambda integration
        lambda_integration = apigateway.LambdaIntegration(fn, proxy=True)

        # Create request validator based on input mode
        # For POST (body mode), validate request body; for GET, validate query parameters
        validate_request_body = (http_method == "POST")
        validate_request_parameters = (http_method == "GET")
        request_validator = apigateway.RequestValidator(self, "RequestValidator",
            rest_api=api,
            request_validator_name=f"{http_method.lower()}-validator",
            validate_request_body=validate_request_body,
            validate_request_parameters=validate_request_parameters
        )

        # Optional: Configure API key and usage plan
        api_key_id = self.node.try_get_context("api_key_id")
        enable_api_key = self.node.try_get_context("enable_api_key")
        
        # Create or use existing API key if enabled
        api_key = None
        usage_plan = None
        if enable_api_key or api_key_id:
            if api_key_id:
                # Use existing API key
                api_key = apigateway.ApiKey.from_api_key_id(self, "ExistingApiKey", api_key_id=api_key_id)
                # Cannot retrieve value for existing API key
                cdk.CfnOutput(self, "ApiKeyId",
                    value=api_key.key_id,
                    description="API Key ID (value cannot be retrieved for existing keys)"
                )
            else:
                # Create new API key
                api_key = apigateway.ApiKey(self, "DyndnsApiKey",
                    api_key_name="dyndns-api-key",
                    description="API key for Dynamic DNS API"
                )

                # Also output the API key ID for reference
                cdk.CfnOutput(self, "ApiKeyId",
                    value=api_key.key_id,
                    description="API Key ID"
                )
            
            # Create usage plan for throttling and rate limiting
            usage_plan_props = {
                "name": "dyndns-usage-plan",
                "description": "Usage plan for Dynamic DNS API",
                "api_stages": [apigateway.UsagePlanPerApiStage(
                    api=api,
                    stage=api.deployment_stage
                )]
            }
            
            # Optional throttling configuration
            throttle_rate_limit = self.node.try_get_context("api_throttle_rate_limit")
            throttle_burst_limit = self.node.try_get_context("api_throttle_burst_limit")
            if throttle_rate_limit is not None or throttle_burst_limit is not None:
                usage_plan_props["throttle"] = apigateway.ThrottleSettings(
                    rate_limit=throttle_rate_limit if throttle_rate_limit is not None else 100,
                    burst_limit=throttle_burst_limit if throttle_burst_limit is not None else 200
                )
            
            # Optional quota configuration
            quota_limit = self.node.try_get_context("api_quota_limit")
            quota_period = self.node.try_get_context("api_quota_period")
            if quota_limit is not None:
                # Map period string to Period enum
                period_map = {
                    "day": apigateway.Period.DAY,
                    "week": apigateway.Period.WEEK,
                    "month": apigateway.Period.MONTH
                }
                period = period_map.get((quota_period or "day").lower(), apigateway.Period.DAY)
                usage_plan_props["quota"] = apigateway.QuotaSettings(
                    limit=quota_limit,
                    period=period
                )
            
            usage_plan = apigateway.UsagePlan(self, "DyndnsUsagePlan", **usage_plan_props)
            
            # Associate API key with usage plan
            usage_plan.add_api_key(api_key)

        # Add method to root resource based on input mode
        # If API key is enabled, require it for authentication
        method_options = {
            "request_validator": request_validator
        }
        
        # For GET method, configure query string parameters
        # For POST method, request body validation is handled by the validator
        if http_method == "GET":
            method_options["request_parameters"] = {
                "method.request.querystring.mode": True,
                "method.request.querystring.execution_mode": False,  # Optional alternative
                "method.request.querystring.hostname": False,  # Optional, only needed for set mode
                "method.request.querystring.set_hostname": False,  # Optional alternative
                "method.request.querystring.ddns_hostname": False,  # Optional alternative
                "method.request.querystring.hash": False,  # Optional, only needed for set mode
                "method.request.querystring.validation_hash": False,  # Optional alternative
                "method.request.querystring.timestamp": False  # Optional, only needed for set mode
            }
        
        if api_key:
            method_options["api_key_required"] = True
        
        api.root.add_method(http_method, lambda_integration, **method_options)

        # Automatically create Route53 DNS record if custom domain and zone info are provided
        if custom_domain_name and certificate_arn and custom_domain and route53_zone_id and route53_zone_name:
            try:
                # Use fromHostedZoneAttributes - requires both zone ID and zone name
                hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
                    self, "HostedZone",
                    hosted_zone_id=route53_zone_id,
                    zone_name=route53_zone_name
                )
                
                zone_name_for_extraction = route53_zone_name
                
                # Extract subdomain from custom_domain_name (e.g., "api" from "api.example.com")
                # If custom_domain_name is the root domain, record_name will be empty
                if custom_domain_name.endswith(zone_name_for_extraction):
                    record_name = custom_domain_name.replace(f".{zone_name_for_extraction}", "")
                    if record_name == zone_name_for_extraction:
                        record_name = ""  # Root domain
                else:
                    # Fallback: use the full domain as record name
                    record_name = custom_domain_name
                
                # Create A record (alias) pointing to API Gateway custom domain
                route53.ARecord(self, "ApiGatewayAliasRecord",
                    zone=hosted_zone,
                    record_name=record_name if record_name else None,  # None for root domain
                    target=route53.RecordTarget.from_alias(
                        route53_targets.ApiGatewayDomain(custom_domain)
                    )
                )
                
                cdk.CfnOutput(self, "Route53RecordCreated",
                    value="Yes",
                    description="Route53 DNS record automatically created"
                )
            except Exception as e:
                # If hosted zone lookup fails, output instructions
                cdk.CfnOutput(self, "Route53SetupRequired",
                    value=f"Manual DNS setup required. Create A record pointing to API Gateway domain.",
                    description=f"Route53 record creation failed - manual setup required: {str(e)}"
                )

        # Output custom domain URL and API Gateway domain name if configured
        if custom_domain_name and certificate_arn:
            cdk.CfnOutput(self, "CustomDomainUrl",
                value=f"https://{custom_domain_name}",
                description="Custom domain URL for the API"
            )
            
            # Output the API Gateway domain name for manual DNS setup if needed
            if custom_domain:
                # Get the regional domain name from the custom domain using CloudFormation attribute
                # This is the domain name that Route53 should point to
                cdk.CfnOutput(self, "ApiGatewayDomainName",
                    value=custom_domain.domain_name_alias_domain_name,
                    description="API Gateway regional domain name - use this for CNAME if Route53 auto-setup didn't work"
                )

        # Output the API Gateway URL
        cdk.CfnOutput(self, "ApiGatewayUrl",
            value=api.url,
            description="API Gateway endpoint URL"
        )

        #Give lambda permissions to read and write DynamoDB table
        # Read: for reading configuration
        # Write: for updating last_checked, last_accessed, last_updated, ip_address
        table.grant_read_write_data(fn)

        #Suppress AwsSolutions-IAM5 triggered by Resources::*
        NagSuppressions.add_resource_suppressions(
            construct= fn_role,
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-IAM5',
                    reason="""
                    Lambda role created at line 29 has 2 inline policies allowing access to Route53 and CloudWatch. 
                    Route53 resources are set to "*" as the function will need to access any hosted zone.
                    CloudWatch resources are set to "*" to avoid having to specify a Logging group and consume the default one deployed by CDK.
                    """
                )
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            "/DyndnsStack/dyndns_api/DeploymentStage.prod/Resource",
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-APIG1',
                    reason="Access logging is optional for this Dynamic DNS service."
                ),
                NagPackSuppression(
                    id = 'AwsSolutions-APIG6',
                    reason="Access logging is optional for this Dynamic DNS service."
                ),
                NagPackSuppression(
                    id = 'AwsSolutions-APIG4',
                    reason="The service uses hash-based authentication in the Lambda function (SHA256 with shared secret). API key authentication is optional and can be enabled via context."
                )
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/DyndnsStack/dyndns_api/Default/{http_method}/Resource",
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-APIG4',
                    reason="The service uses hash-based authentication in the Lambda function (SHA256 with shared secret), which is the intended security model."
                )
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            "/DyndnsStack/dyndns_api/Resource",
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-APIG2',
                    reason="Request validation enabled at operation level."
                )
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/DyndnsStack/dyndns_api/Default/{http_method}/Resource",
            suppressions=[
                NagPackSuppression(
                    id = 'AwsSolutions-APIG4',
                    reason="The service uses hash-based authentication in the Lambda function (SHA256 with shared secret). API key authentication is optional and can be enabled via context."
                ),
                NagPackSuppression(
                    id = 'AwsSolutions-COG4',
                    reason="The service uses hash-based authentication in the Lambda function (SHA256 with shared secret). API key authentication is optional and can be enabled via context."
                )
            ]
        )