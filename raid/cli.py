import argparse
import logging
import sys

from .version import __version__
from .core.engine import Engine
from .core.workflow import Workflow


def setup_logging(verbose: bool = False):
    "Set up logging."
    # Keep output quiet unless verbose mode is enabled.
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def list_plugins(engine: Engine):
    "Print all available plugins."
    print("Available Parsers:")
    for parser in engine.list_parsers():
        print(f"  - {parser}")
    
    print("\nAvailable Detectors:")
    for detector in engine.list_detectors():
        print(f"  - {detector}")


def main():
    "Run the CLI."
    example = (
        "Example usage:\n"
        "Parse a Windows event log file:\n"
        "python -m raid run -i path/to/the/windows_event_file -p windows_event_log -d suspicious_user_detector\n"
        "(replace plugins and file path with the ones you have installed)"
    )

    parser = argparse.ArgumentParser(
        prog='python -m raid',
        description='R.A.I.D. - Threat Hunting Framework',
        epilog=example,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # run command
    run_parser = subparsers.add_parser(
        'run',
        help='Run the R.A.I.D. workflow',
        prog='python -m raid run',
        epilog=(
            'Example:\n'
            '  python -m raid run -i /home/desktop/Powershell-Operational.evtx '
            '-p windows_event_log -d suspicious_user_detector [-o OUTPUT]'
        ),
    )
    run_parser.add_argument('-i', '--input', action='append', required=True, 
                           help='Input log file or folder (can be specified multiple times)')
    run_parser.add_argument('-p', '--parser', required=True, 
                           help='Parser plugin to use')
    run_parser.add_argument('-d', '--detector', action='append', required=True,
                           help='Detector plugin to use (can be specified multiple times)')
    run_parser.add_argument('-o', '--output', help='Output file for the report')
    
    # list command
    subparsers.add_parser('list', help='List available plugins')
    
    args = parser.parse_args()
    
    # Set up logging.
    setup_logging(args.verbose)
    
    # Load engine and plugins.
    engine = Engine(args.config)
    engine.load_plugins()
    
    if args.command == 'list':
        list_plugins(engine)
    elif args.command == 'run':
        workflow = Workflow(engine)
        results = workflow.execute(
            input_files=args.input,
            parser_name=args.parser,
            detector_names=args.detector,
            output_file=args.output
        )
        
        # Print summary.
        print("\n--- Summary ---")
        print(f">Processed {results['redact']['records_processed']} records from {results['redact']['files_processed']} files")
        print(f">Found {results['assess']['total_findings']} potential threats using {results['assess']['detectors_run']} detectors")
        print(f">Identified {results['integrate']['correlations_identified']} correlations")
        print(f">Report generated and saved to {results['deploy']['output_file']}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()