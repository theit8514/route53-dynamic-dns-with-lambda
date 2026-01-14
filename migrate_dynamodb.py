#!/usr/bin/env python3
"""
Migration script to migrate DynamoDB items to new format.

Fields migrated:
- ttl -> route_53_record_ttl (converted to number type, old ttl field removed)

New fields added:
- route_53_zone_id (required for Lambda function)

Fields preserved (for other processes):
- hostname, record_type, comment, company, ip_address, last_accessed, 
  last_checked, last_updated, lock_record, shared_secret
"""

import boto3
import sys
import argparse
from botocore.exceptions import ClientError

def migrate_table(table_name, zone_id, dry_run=True, profile=None, region=None):
    """
    Migrate DynamoDB table from old format to new format.
    
    Args:
        table_name: Name of the DynamoDB table
        zone_id: Route53 hosted zone ID to add to all records
        dry_run: If True, only show what would be changed without making updates
        profile: AWS profile name to use (optional)
        region: AWS region name to use (optional)
    """
    # Create session with profile if specified
    session_kwargs = {}
    if profile:
        session_kwargs['profile_name'] = profile
    
    session = boto3.Session(**session_kwargs)
    
    # Create DynamoDB client with region if specified
    client_kwargs = {}
    if region:
        client_kwargs['region_name'] = region
    
    dynamodb = session.client('dynamodb', **client_kwargs)
    
    print(f'Table: {table_name}')
    print(f'Zone ID: {zone_id}')
    print(f'Mode: {"DRY RUN (no changes will be made)" if dry_run else "LIVE (changes will be applied)"}')
    print('=' * 80)
    
    # Scan all items
    print('\nScanning table...')
    items_to_migrate = []
    scan_kwargs = {}
    
    try:
        while True:
            response = dynamodb.scan(TableName=table_name, **scan_kwargs)
            items_to_migrate.extend(response.get('Items', []))
            
            if 'LastEvaluatedKey' not in response:
                break
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
        
        print(f'Found {len(items_to_migrate)} items to process\n')
        
        if len(items_to_migrate) == 0:
            print('No items found in table.')
            return
        
        # Process each item
        migrated_count = 0
        skipped_count = 0
        error_count = 0
        
        for item in items_to_migrate:
            try:
                # Extract hostname (required)
                if 'hostname' not in item:
                    print(f'⚠️  Skipping item: missing hostname')
                    print(f'   Item keys: {list(item.keys())}')
                    skipped_count += 1
                    continue
                
                hostname = item['hostname'].get('S', '')
                if not hostname:
                    print(f'⚠️  Skipping item: empty hostname')
                    skipped_count += 1
                    continue
                
                print(f'Processing: {hostname}')
                
                # Check if already migrated (has route_53_zone_id)
                if 'route_53_zone_id' in item:
                    print(f'  ✓ Already migrated, skipping')
                    skipped_count += 1
                    continue
                
                # Extract shared_secret (optional - missing indicates record can't be updated)
                shared_secret = item.get('shared_secret', {}).get('S', '')
                if not shared_secret:
                    print(f'  ⚠️  Note: missing shared_secret (record cannot be updated via API)')
                
                # Extract TTL (could be 'ttl' or 'route_53_record_ttl')
                ttl_value = None
                if 'ttl' in item:
                    ttl_attr = item['ttl']
                    if 'N' in ttl_attr:
                        ttl_value = ttl_attr['N']
                    elif 'S' in ttl_attr:
                        ttl_value = ttl_attr['S']
                elif 'route_53_record_ttl' in item:
                    ttl_attr = item['route_53_record_ttl']
                    if 'N' in ttl_attr:
                        ttl_value = ttl_attr['N']
                    elif 'S' in ttl_attr:
                        ttl_value = ttl_attr['S']
                
                if not ttl_value:
                    print(f'  ⚠️  Warning: missing ttl, defaulting to 300')
                    ttl_value = '300'
                
                # Build new item structure
                # Note: shared_secret is optional - if missing, record cannot be updated via API
                new_item = {
                    'hostname': item['hostname'],  # Keep as-is
                    'route_53_zone_id': {'S': zone_id},
                    'route_53_record_ttl': {'N': str(ttl_value)}  # Store as number
                }
                
                # Only add shared_secret if it exists
                if shared_secret:
                    new_item['shared_secret'] = {'S': shared_secret}
                elif 'shared_secret' in item:
                    # Preserve existing shared_secret field even if empty
                    new_item['shared_secret'] = item['shared_secret']
                
                # Preserve tracking fields if they exist
                for field in ['ip_address', 'last_accessed', 'last_checked', 'last_updated']:
                    if field in item:
                        new_item[field] = item[field]
                
                # Show what will be changed
                print(f'  Adding: route_53_zone_id = {zone_id}')
                print(f'  Migrating: ttl -> route_53_record_ttl = {ttl_value} (as number)')
                if 'ttl' in item:
                    print(f'  Removing: old ttl field')
                
                # Update the item
                if not dry_run:
                    # Build update expression
                    update_expr_parts = []
                    remove_expr_parts = []
                    expr_attr_values = {}
                    expr_attr_names = {}
                    
                    # Add route_53_zone_id
                    update_expr_parts.append('#zone_id = :zone_id')
                    expr_attr_names['#zone_id'] = 'route_53_zone_id'
                    expr_attr_values[':zone_id'] = {'S': zone_id}
                    
                    # Add route_53_record_ttl
                    update_expr_parts.append('#ttl = :ttl')
                    expr_attr_names['#ttl'] = 'route_53_record_ttl'
                    expr_attr_values[':ttl'] = {'N': str(ttl_value)}
                    
                    # Remove old ttl field if it exists (ttl is a reserved keyword, so use ExpressionAttributeNames)
                    if 'ttl' in item:
                        remove_expr_parts.append('#ttl_old')
                        expr_attr_names['#ttl_old'] = 'ttl'
                    
                    # Build the update expression
                    update_expression = 'SET ' + ', '.join(update_expr_parts)
                    if remove_expr_parts:
                        update_expression += ' REMOVE ' + ', '.join(remove_expr_parts)
                    
                    try:
                        dynamodb.update_item(
                            TableName=table_name,
                            Key={'hostname': item['hostname']},
                            UpdateExpression=update_expression,
                            ExpressionAttributeNames=expr_attr_names,
                            ExpressionAttributeValues=expr_attr_values
                        )
                        print(f'  ✓ Migrated successfully')
                        migrated_count += 1
                    except ClientError as e:
                        print(f'  ✗ Error: {e}')
                        error_count += 1
                else:
                    print(f'  [DRY RUN] Would migrate')
                    migrated_count += 1
                
                print()
                
            except Exception as e:
                print(f'  ✗ Error processing item: {e}')
                error_count += 1
                print()
        
        # Summary
        print('=' * 80)
        print('Migration Summary:')
        print(f'  Total items: {len(items_to_migrate)}')
        print(f'  Migrated: {migrated_count}')
        print(f'  Skipped: {skipped_count}')
        print(f'  Errors: {error_count}')
        
        if dry_run:
            print('\nThis was a DRY RUN. No changes were made.')
            print('Run with --execute to apply changes.')
        else:
            print('\nMigration completed!')
    
    except ClientError as e:
        print(f'Error accessing DynamoDB: {e}')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Migrate DynamoDB table from old format to new format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Dry run (preview changes)
  python migrate_dynamodb.py --table MyTable --zone-id Z1234567890ABC
  
  # Execute migration
  python migrate_dynamodb.py --table MyTable --zone-id Z1234567890ABC --execute
  
  # Use specific AWS profile and region
  python migrate_dynamodb.py --table MyTable --zone-id Z1234567890ABC --profile myprofile --region us-east-1
        '''
    )
    parser.add_argument('--table', required=True, help='DynamoDB table name')
    parser.add_argument('--zone-id', required=True, help='Route53 hosted zone ID to add to all records')
    parser.add_argument('--execute', action='store_true', help='Execute migration (default is dry-run)')
    parser.add_argument('--profile', help='AWS profile name to use (from ~/.aws/credentials)')
    parser.add_argument('--region', help='AWS region name (e.g., us-east-1, eu-west-1)')
    
    args = parser.parse_args()
    
    dry_run = not args.execute
    
    if not dry_run:
        print('⚠️  WARNING: This will modify your DynamoDB table!')
        response = input('Type "yes" to continue: ')
        if response.lower() != 'yes':
            print('Aborted.')
            sys.exit(0)
    
    # Show configuration
    if args.profile:
        print(f'Using AWS profile: {args.profile}')
    if args.region:
        print(f'Using AWS region: {args.region}')
    print()
    
    migrate_table(args.table, args.zone_id, dry_run=dry_run, profile=args.profile, region=args.region)


if __name__ == '__main__':
    main()
