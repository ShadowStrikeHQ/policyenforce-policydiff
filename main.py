import argparse
import json
import logging
import sys
import jsondiffpatch
import jsonschema
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Compare two security policies and highlight the differences.")
    parser.add_argument("policy_file1", help="Path to the first security policy file (JSON or YAML).")
    parser.add_argument("policy_file2", help="Path to the second security policy file (JSON or YAML).")
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format (json or yaml). Defaults to json.",
    )
    parser.add_argument(
        "--schema",
        help="Path to the JSON schema file for validating policies.",
    )
    return parser

def load_policy(policy_file):
    """
    Loads a security policy from a file (JSON or YAML).

    Args:
        policy_file (str): Path to the policy file.

    Returns:
        dict: The loaded policy as a dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is invalid.
    """
    try:
        with open(policy_file, 'r') as f:
            if policy_file.endswith('.json'):
                return json.load(f)
            elif policy_file.endswith(('.yaml', '.yml')):
                return yaml.safe_load(f)
            else:
                raise ValueError("Unsupported file format. Use JSON or YAML.")
    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON file: {policy_file} - {e}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error decoding YAML file: {policy_file} - {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading policy file: {policy_file} - {e}")
        raise


def validate_policy(policy, schema_file=None):
    """
    Validates a policy against a JSON schema.

    Args:
        policy (dict): The policy to validate.
        schema_file (str, optional): Path to the JSON schema file. Defaults to None.

    Raises:
        jsonschema.exceptions.ValidationError: If the policy is invalid.
        FileNotFoundError: If the schema file does not exist.
    """
    if schema_file:
        try:
            with open(schema_file, 'r') as f:
                schema = json.load(f)
            jsonschema.validate(policy, schema)
            logging.info("Policy validated successfully against the schema.")
        except FileNotFoundError:
            logging.error(f"Schema file not found: {schema_file}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding schema file: {schema_file} - {e}")
            raise
        except jsonschema.exceptions.ValidationError as e:
            logging.error(f"Policy validation failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Error validating policy: {e}")
            raise


def diff_policies(policy1, policy2):
    """
    Compares two security policies and returns the differences.

    Args:
        policy1 (dict): The first policy.
        policy2 (dict): The second policy.

    Returns:
        dict: A dictionary representing the differences between the policies.
    """
    differ = jsondiffpatch.JsonDiffer()
    diff = differ.diff(policy1, policy2)
    return diff

def print_diff(diff, output_format="json"):
    """
    Prints the policy differences in the specified format (JSON or YAML).

    Args:
        diff (dict): The policy differences.
        output_format (str): The output format ("json" or "yaml"). Defaults to "json".
    """
    if diff:
        try:
            if output_format == "json":
                print(json.dumps(diff, indent=4))
            elif output_format == "yaml":
                print(yaml.dump(diff, indent=2))
            else:
                logging.error(f"Invalid output format: {output_format}")
                raise ValueError(f"Invalid output format: {output_format}")
        except Exception as e:
            logging.error(f"Error printing diff: {e}")
            raise

def main():
    """
    Main function to execute the policy comparison.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        policy1 = load_policy(args.policy_file1)
        policy2 = load_policy(args.policy_file2)

        if args.schema:
            validate_policy(policy1, args.schema)
            validate_policy(policy2, args.schema)

        diff = diff_policies(policy1, policy2)

        if diff:
            print_diff(diff, args.format)
        else:
            logging.info("Policies are identical.")

    except FileNotFoundError:
        sys.exit(1)
    except ValueError as e:
        logging.error(e)
        sys.exit(1)
    except jsonschema.exceptions.ValidationError:
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()