# policyenforce-PolicyDiff
A command-line tool that compares two security policies (e.g., represented as JSON or YAML files) and highlights the differences, particularly focusing on permissions, allowed actions, and resource constraints.  Uses `jsondiffpatch` for efficient comparison. - Focused on Provides tools to programmatically enforce security policies across systems, such as verifying configuration files against a predefined schema and reporting deviations.

## Install
`git clone https://github.com/ShadowStrikeHQ/policyenforce-policydiff`

## Usage
`./policyenforce-policydiff [params]`

## Parameters
- `-h`: Show help message and exit
- `--format`: No description provided
- `--schema`: Path to the JSON schema file for validating policies.

## License
Copyright (c) ShadowStrikeHQ
