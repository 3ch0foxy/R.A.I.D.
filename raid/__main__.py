"""Module entry point for `python -m raid`."""

import sys
from . import version
from . import cli

def main():
    args = sys.argv[1:]
    if '--version' in args or '-V' in args:
        print(version.__version__)
        return

    # Hand off to the CLI parser.
    cli.main()

if __name__ == '__main__':
    main()
