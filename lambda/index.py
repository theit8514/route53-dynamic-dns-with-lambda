# Dynamic DNS via AWS API Gateway, Lambda & Route 53
# Script variables use lower_case_

from __future__ import print_function

import json
import re
import hashlib
import boto3
import os
import datetime
import dateutil.parser
from botocore.exceptions import ClientError

'''
This function pulls the json config data from DynamoDB and returns a python dictionary.
It also updates last_checked and last_accessed fields in DynamoDB.
It is called by the run_set_mode function.
@param key_hostname: The normalized hostname to look up in DynamoDB
@param source_ip: The client's IP address making the request
@return The config dictionary parsed from the DynamoDB data attribute
'''
def read_config(key_hostname, source_ip):
    # Define the dynamoDB client
    dynamodb = boto3.client("dynamodb")
    table_name = os.environ.get("ddns_config_table")
    # Retrieve data based on key_hostname
    response = dynamodb.get_item(
        TableName=table_name,
        Key={'hostname': {'S': key_hostname}}
    )

    # Check if the item exists
    if 'Item' not in response:
        print(f'## READ_CONFIG - ERROR: Configuration not found for hostname: {key_hostname}')
        raise KeyError(f'Configuration not found for hostname: {key_hostname}')

    item = response["Item"]
    
    # Support both formats: individual fields (new) or data field with JSON (legacy)
    if 'data' in item:
        # Legacy format: parse JSON from data field
        data_string = item["data"]["S"]
        parsed_config = json.loads(data_string)
    else:
        # New format: read from individual fields
        required_fields = ['shared_secret', 'route_53_zone_id', 'route_53_record_ttl']
        missing_fields = [field for field in required_fields if field not in item]
        
        if missing_fields:
            print(f'## READ_CONFIG - ERROR: Missing required fields: {missing_fields}')
            print(f'  Available attributes: {list(item.keys())}')
            raise KeyError(f'Missing required configuration fields for hostname {key_hostname}: {missing_fields}')
        
        # Extract values from DynamoDB attribute format
        # DynamoDB stores strings as {'S': 'value'}, numbers as {'N': 'value'}
        def get_string_value(field_name):
            if field_name not in item:
                return None
            attr = item[field_name]
            if 'S' in attr:
                return attr['S']
            elif 'N' in attr:
                return attr['N']  # Return as string, will convert to int if needed
            else:
                raise ValueError(f'Unexpected attribute type for {field_name}: {list(attr.keys())}')
        
        parsed_config = {
            'shared_secret': get_string_value('shared_secret'),
            'route_53_zone_id': get_string_value('route_53_zone_id'),
            'route_53_record_ttl': int(get_string_value('route_53_record_ttl'))  # Convert TTL to int
        }

    # Update last_checked and last_accessed in DynamoDB
    try:
        dynamodb.update_item(
            TableName=table_name,
            Key={'hostname': {'S': key_hostname}},
            UpdateExpression='SET last_checked = :now_time, last_accessed = :last_accessed',
            ConditionExpression='attribute_exists(hostname)',
            ExpressionAttributeValues={
                ':now_time': {'S': str(datetime.datetime.now(datetime.timezone.utc))},
                ':last_accessed': {'S': source_ip}
            }
        )
    except Exception as e:
        # If update fails, continue anyway - we still have the config data
        print(f'## READ_CONFIG - Warning: Failed to update last_checked/last_accessed: {e}')
        pass
    
    return parsed_config


'''
This function updates the DynamoDB table with last_updated, ip_address, and last_accessed.
It is called after successfully updating a Route53 record.
@param key_hostname: The normalized hostname to update in DynamoDB
@param source_ip: The client's IP address making the request
'''
def update_dynamodb_record(key_hostname, source_ip):
    # Define the dynamoDB client
    dynamodb = boto3.client("dynamodb")
    try:
        dynamodb.update_item(
            TableName=os.environ.get("ddns_config_table"),
            Key={'hostname': {'S': key_hostname}},
            UpdateExpression='SET last_updated = :now_time, ip_address = :ip, last_accessed = :last_accessed',
            ConditionExpression='attribute_exists(hostname)',
            ExpressionAttributeValues={
                ':now_time': {'S': str(datetime.datetime.now(datetime.timezone.utc))},
                ':ip': {'S': source_ip},
                ':last_accessed': {'S': source_ip}
            }
        )
    except Exception as e:
        # Log error but don't fail the request
        print(f'Error updating DynamoDB record for {key_hostname}: {str(e)}')


'''
This function takes the python dictionary returned from read_config
This function defines the interaction with Route 53.
It is called by the run_set_mode function.
@param execution_mode defines whether to set or get a DNS record
@param route_53_zone_id defines the id for the DNS zone
@param route_53_record_name defines the record, ie www.acme.com.
@param route_53_record_ttl defines defines the DNS record TTL
@param route_53_record_type defines record type, should always be 'a'
@param public_ip defines the current public ip of the client
'''
def route53_client(execution_mode, route_53_zone_id,
                   route_53_record_name, route_53_record_ttl,
                   route_53_record_type, public_ip):
    # Define the Route 53 client
    route53_client = boto3.client('route53')

    # Query Route 53 for the current DNS record.
    if execution_mode == 'get_record':
        try:
            current_route53_record_set = route53_client.list_resource_record_sets(
                HostedZoneId=route_53_zone_id,
                StartRecordName=route_53_record_name,
                StartRecordType=route_53_record_type,
                MaxItems='1'
            )
            try:
                if current_route53_record_set['ResourceRecordSets'][0]['Name'].rstrip('.') == route_53_record_name.rstrip('.'):
                    currentroute53_ip = current_route53_record_set['ResourceRecordSets'][0]['ResourceRecords'][0]['Value']
                else:
                    currentroute53_ip = '0'
            except:
                currentroute53_ip = '0'
            return {'status_code': 200,
                    'return_status': 'success',
                    'return_message': currentroute53_ip}
        except ClientError as e:
            return {'status_code': 500,
                    'return_status': 'fail',
                    'return_message': str(e)}
        except:
            return {'status_code': 500,
                    'return_status': 'fail',
                    'return_message': 'Unknown error'}

    # Set the DNS record to the current IP.
    if execution_mode == 'set_record':
        try:
            change_route53_record_set = route53_client.change_resource_record_sets(
                HostedZoneId = route_53_zone_id,
                ChangeBatch = {
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': route_53_record_name,
                                'Type': route_53_record_type,
                                'TTL': route_53_record_ttl,
                                'ResourceRecords': [
                                    {
                                        'Value': public_ip
                                    }
                                ]
                            }
                        }
                    ]
                }
            )
            return {'status_code': 201,
                    'return_status': 'success',
                    'return_message': route_53_record_name+' has been updated to '+public_ip}
        except ClientError as e:
            return {'status_code': 500,
                    'return_status': 'fail',
                    'return_message': str(e)}
        except:
            return {'status_code': 500,
                    'return_status': 'fail',
                    'return_message': 'Unknown error'}


'''
This function calls route53_client to see if the current Route 53 DNS record matches the client's current IP.
If not it calls route53_client to set the DNS record to the current IP.
It is called by the main lambda_handler function.
'''
def run_set_mode(ddns_hostname, validation_hash, source_ip, timestamp):
    normalized_hostname = normalize_hostname(ddns_hostname)
    # Try to read the config, and error if you can't.
    try:
        full_config=read_config(normalized_hostname, source_ip)
    except KeyError as e:
        print(f"Configuration not found for {ddns_hostname} (lookup key: {normalized_hostname}): {e}")
        return {'status_code': 404,
                'return_status': 'fail',
                'return_message': f'Configuration not found for hostname: {ddns_hostname}. Please ensure the hostname is registered in the DynamoDB table.'}
    except Exception as e:
        print(f"Error reading config for {ddns_hostname}: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {'status_code': 500,
                'return_status': 'fail',
                'return_message': f'There was an issue finding or reading {ddns_hostname} configuration from DynamoDB table: {str(e)}'}

    # Get the section of the config related to the requested hostname.
    record_config_set=full_config  # [ddns_hostname]
    # the Route 53 Zone you created for the script
    route_53_zone_id=record_config_set['route_53_zone_id']
    # record TTL (Time To Live) in seconds tells DNS servers how long to cache
    # the record.
    route_53_record_ttl=record_config_set['route_53_record_ttl']
    route_53_record_type="A"
    shared_secret=record_config_set['shared_secret']

    # Validate that the client passed a sha256 hash
    # regex checks for a 64 character hex string.
    if not re.match(r'[0-9a-fA-F]{64}', validation_hash):
        return {'status_code': 400,
                'return_status': 'fail',
                'return_message': 'You must pass a valid sha256 hash in the '\
                    'hash= argument.'}
    if not validate_hash(normalized_hostname, source_ip, validation_hash, shared_secret, timestamp):
        return {'status_code': 401,
                'return_status': 'fail',
                'return_message': 'Validation hashes do not match.'}

    # If they do match, get the current ip address associated with
    # the hostname DNS record from Route 53.
    route53_get_response=route53_client(
        'get_record',
        route_53_zone_id,
        normalized_hostname,
        route_53_record_ttl,
        route_53_record_type,
        '')
    # If no records were found, route53_client returns null.
    # Set route53_ip and stop evaluating the null response.
    if route53_get_response['return_status'] == "fail":
        return {'status_code': 500,
                'return_status': route53_get_response['return_status'],
                'return_message': route53_get_response['return_message']}
    else:
        route53_ip = route53_get_response['return_message']
    # If the client's current IP matches the current DNS record
    # in Route 53 there is nothing left to do.
    if route53_ip == source_ip:
        return_status = 'success'
        return_message = 'Your IP address matches '\
            'the current Route53 DNS record.'
        return {'status_code': 200,
                'return_status': return_status,
                'return_message': return_message}
    # If the IP addresses do not match or if the record does not exist,
    # Tell Route 53 to set the DNS record.
    else:
        return_status = route53_client(
            'set_record',
            route_53_zone_id,
            normalized_hostname,
            route_53_record_ttl,
            route_53_record_type,
            source_ip)
        # If Route53 update was successful, update DynamoDB with tracking information
        if return_status['return_status'] == 'success':
            update_dynamodb_record(normalized_hostname, source_ip)
        return return_status


'''
This function normalizes the hostname to lowercase and adds a trailing dot if not present.
It is called by the run_set_mode function.
@param ddns_hostname: The DNS hostname to be updated.
@return The normalized hostname.
'''
def normalize_hostname(ddns_hostname):
    if not ddns_hostname.endswith('.'):
        ddns_hostname += '.'
    return ddns_hostname


'''
Validates that a client-supplied hash matches the expected hash
generated from the IP address, hostname, shared secret, and timestamp.
The timestamp is required for security and helps prevent replay attacks.

@param normalized_hostname: The normalized hostname to be updated.
@param source_ip: The client's IP address making the request.
@param validation_hash: The hash value provided by the client for validation.
@param shared_secret: Shared secret used to compute the hash.
@param timestamp: ISO8601-formatted timestamp provided by the client.
@return True if the hash matches, False otherwise
'''
def validate_hash(normalized_hostname, source_ip, validation_hash, shared_secret, timestamp):
    # Calculate the validation hash with timestamp: source_ip|hostname|secret|timestamp
    input = source_ip + '|' + normalized_hostname + '|' + shared_secret + '|' + timestamp
    calculated_hash = hashlib.sha256(input.encode('utf-8')).hexdigest()
    # Compare the validation_hash from the client to the
    # calculated_hash.
    # If they don't match, error out.
    return calculated_hash == validation_hash


'''
This function validates the timestamp is the correct format and is within the last 5 minutes.
It is called by the main lambda_handler function.
@param timestamp the timestamp of the request
@return True if the timestamp is valid, False otherwise
'''
def validate_timestamp(timestamp):
    # Validate timestamp format
    if not timestamp:
        print('## VALIDATE TIMESTAMP - Failed: timestamp is None or empty')
        return False
    
    if not re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', timestamp):
        print(f'## VALIDATE TIMESTAMP - Failed: format does not match regex pattern')
        return False
    
    try:
        parsed_timestamp = dateutil.parser.parse(timestamp)
        # Ensure parsed timestamp is timezone-aware (default to UTC if naive)
        if parsed_timestamp.tzinfo is None:
            print('## VALIDATE TIMESTAMP - Warning: parsed timestamp is naive, assuming UTC')
            parsed_timestamp = parsed_timestamp.replace(tzinfo=datetime.timezone.utc)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        time_diff_seconds = abs((now - parsed_timestamp).total_seconds())
        print(f'## VALIDATE TIMESTAMP - Time difference: {time_diff_seconds} seconds')
        
        if time_diff_seconds > 300:
            print(f'## VALIDATE TIMESTAMP - Failed: time difference ({time_diff_seconds}s) exceeds 5 minutes (300s)')
            return False
        else:
            print('## VALIDATE TIMESTAMP - Success: timestamp is valid')
            return True
    except Exception as e:
        print(f'## VALIDATE TIMESTAMP - Exception: {str(e)}')
        import traceback
        print(f'## VALIDATE TIMESTAMP - Traceback: {traceback.format_exc()}')
        return False


'''
Helper function to extract parameters from event based on input mode.
Supports both 'body' (Function URL) and 'queryStringParameters' (API Gateway) modes.
@param event: The Lambda event object
@param input_mode: The mode indicating where to extract parameters from the event ('body' for Function URL, 'queryStringParameters' for API Gateway)
@return Dictionary with extracted parameters or None if extraction fails
'''
def extract_event_parameters(event, input_mode):
    print('## ENVIRONMENT VARIABLES')
    print(os.environ)
    print('## EVENT')
    print(event)
    print('## INPUT MODE')
    print(input_mode)
    try:
        if input_mode == 'queryStringParameters':
            # API Gateway mode - read from queryStringParameters
            params = event.get('queryStringParameters') or {}
            print('## QUERY STRING PARAMETERS (raw)')
            print(params)
            extracted = {
                'execution_mode': params.get('mode') or params.get('execution_mode'),
                'validation_hash': params.get('validation_hash') or params.get('hash'),
                'ddns_hostname': params.get('ddns_hostname') or params.get('hostname') or params.get('set_hostname'),
                'timestamp': params.get('timestamp')
            }
            print('## EXTRACTED PARAMETERS')
            print(f'execution_mode: {extracted["execution_mode"]}')
            print(f'validation_hash: {extracted["validation_hash"]}')
            print(f'ddns_hostname: {extracted["ddns_hostname"]}')
            print(f'timestamp: {extracted["timestamp"]} (type: {type(extracted["timestamp"])})')
            return extracted
        else:
            # Default: Function URL mode - read from body
            body = json.loads(event.get('body', '{}'))
            print('## BODY (parsed)')
            print(body)
            extracted = {
                'execution_mode': body.get('mode') or body.get('execution_mode'),
                'validation_hash': body.get('validation_hash') or body.get('hash'),
                'ddns_hostname': body.get('ddns_hostname') or body.get('hostname') or body.get('set_hostname'),
                'timestamp': body.get('timestamp')
            }
            print('## EXTRACTED PARAMETERS')
            print(f'execution_mode: {extracted["execution_mode"]}')
            print(f'validation_hash: {extracted["validation_hash"]}')
            print(f'ddns_hostname: {extracted["ddns_hostname"]}')
            print(f'timestamp: {extracted["timestamp"]} (type: {type(extracted["timestamp"])})')
            return extracted
    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        print(f'## ERROR EXTRACTING PARAMETERS: {str(e)}')
        return None


'''
Helper function to extract source IP from event based on event structure.
Supports both Function URL and API Gateway event formats.
@param event: The Lambda event object
@return The source IP address or None if not found
'''
def extract_source_ip(event):
    # Try Function URL format first
    try:
        if 'requestContext' in event and 'http' in event['requestContext']:
            return event['requestContext']['http'].get('sourceIp')
    except (KeyError, AttributeError, TypeError):
        pass
    
    # Try API Gateway format
    try:
        if 'requestContext' in event and 'identity' in event['requestContext']:
            return event['requestContext']['identity'].get('sourceIp')
    except (KeyError, AttributeError, TypeError):
        pass
    
    # Try alternative API Gateway format
    try:
        if 'requestContext' in event:
            return event['requestContext'].get('sourceIp')
    except (KeyError, AttributeError, TypeError):
        pass
    
    return None


'''
The function that Lambda executes. It contains the main script logic.
'''
def lambda_handler(event, context):
    # Determine allowed methods based on input mode
    input_mode = os.environ.get('input_mode', 'body')
    # Extract parameters based on input mode
    params = extract_event_parameters(event, input_mode)
    if params is None:
        return_dict = {
            'status_code': 400,
            'return_status': 'fail',
            'return_message': 'Invalid request format. Unable to parse parameters.'
        }
    else:
        # Extract source IP from event
        source_ip = extract_source_ip(event)
        if not source_ip:
            return_dict = {
                'status_code': 400,
                'return_status': 'fail',
                'return_message': 'Unable to determine source IP address.'
            }
        else:
            execution_mode = params.get('execution_mode')
            
            # Verify that the execution mode was set correctly.
            execution_modes = ('set', 'get')
            if not execution_mode or execution_mode not in execution_modes:
                return_dict = {
                    'status_code': 400,
                    'return_status': 'fail',
                    'return_message': 'You must pass execution_mode=get or execution_mode=set arguments.'
                }
            # For get mode, reflect the client's public IP address and exit.
            elif execution_mode == 'get':
                return_dict = {
                    'status_code': 200,
                    'return_status': 'success',
                    'return_message': source_ip
                }
            # Proceed with set mode to create or update the DNS record.
            else:
                validation_hash = params.get('validation_hash')
                ddns_hostname = params.get('ddns_hostname')
                timestamp = params.get('timestamp')
                
                print('## SET MODE PARAMETERS')
                print(f'validation_hash: {validation_hash}')
                print(f'ddns_hostname: {ddns_hostname}')
                print(f'timestamp: {timestamp} (type: {type(timestamp)})')
                
                if not ddns_hostname:
                    return_dict = {
                        'status_code': 400,
                        'return_status': 'fail',
                        'return_message': 'You must pass a hostname, set_hostname, or ddns_hostname argument.'
                    }
                elif not validation_hash:
                    return_dict = {
                        'status_code': 400,
                        'return_status': 'fail',
                        'return_message': 'You must pass a hash or validation_hash argument.'
                    }
                elif not timestamp:
                    return_dict = {
                        'status_code': 400,
                        'return_status': 'fail',
                        'return_message': 'You must pass a timestamp argument.'
                    }
                else:
                    print('## BEFORE TIMESTAMP VALIDATION')
                    timestamp_validation_result = validate_timestamp(timestamp)
                    print(f'## TIMESTAMP VALIDATION RESULT: {timestamp_validation_result}')
                    if not timestamp_validation_result:
                        print('## TIMESTAMP VALIDATION FAILED - Setting error message')
                        return_dict = {
                            'status_code': 400,
                            'return_status': 'fail',
                            'return_message': 'You must pass a timestamp in ISO 8601 format in the '\
                                'timestamp= argument. It must be within 5 minutes of the server.'
                        }
                    else:
                        print('## TIMESTAMP VALIDATION PASSED - Calling run_set_mode')
                        return_dict = run_set_mode(ddns_hostname, validation_hash, source_ip, timestamp)
                        print(f'## RUN_SET_MODE RETURNED: {return_dict}')

    # This Lambda function always exits as a success
    # and passes success or failure information in the json message.
    # return json.loads(return_dict)

    allowed_methods = 'POST' if input_mode == 'body' else 'GET'
    return {
        "statusCode": return_dict['status_code'],
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': allowed_methods
        },
        "body": json.dumps({'return_status': return_dict['return_status'],
                             'return_message': return_dict['return_message']})
    }
