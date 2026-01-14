#!/usr/bin/env python3
import os
import json

import aws_cdk as cdk
from aws_cdk import Aspects
from cdk_nag import AwsSolutionsChecks


from dyndns.dyndns_stack import DyndnsStack


def load_context_from_config(app: cdk.App):
    """
    Load context parameters from a config file if it exists.
    Supports both cdk-config.json and config.json (in that order).
    """
    config_files = ['cdk-config.json', 'config.json']
    
    for config_file in config_files:
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Set each key-value pair as CDK context
                    for key, value in config.items():
                        if value is not None:  # Skip null values
                            app.node.set_context(key, value)
                    print(f'Loaded context from {config_file}')
                    return
            except json.JSONDecodeError as e:
                print(f'Warning: Failed to parse {config_file}: {e}')
            except Exception as e:
                print(f'Warning: Failed to load {config_file}: {e}')


app = cdk.App()

# Load context from config file if it exists
load_context_from_config(app)

DyndnsStack(app, "DyndnsStack")
Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
app.synth()
