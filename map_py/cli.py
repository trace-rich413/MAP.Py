"""Command-line interface for MAP.Py."""

import sys
import argparse

from map_py.config import load_scope
from map_py.runner import run_scope

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='MAP.Py - Scope-aware recon + enumeration orchestrator for Kali',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mappy scopes/example.yaml
  mappy --help
        """
    )
    
    parser.add_argument(
        'scope_file',
        metavar='SCOPE',
        help='Path to scope YAML file'
    )
    
    args = parser.parse_args()
    
    # Load scope
    scope = load_scope(args.scope_file)
    
    # Run reconnaissance
    summary = run_scope(scope)
    
    sys.exit(0)


if __name__ == '__main__':
    main()