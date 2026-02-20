import os
from typing import List, Dict, Any
from ..utils.io import write_json, write_text
from ..utils.reporting import ReportGenerator


class Workflow:
    # Main execution flow for R.A.I.D.
    def __init__(self, engine):
        self.engine = engine
        self.report_generator = ReportGenerator()

    def execute(
        self,
        input_files: List[str],
        parser_name: str,
        detector_names: List[str],
        output_file: str = None,
    ) -> Dict[str, Any]:
        # Expand input values into a final list of files.
        resolved_inputs = self._expand_input_paths(input_files)

        # Step 1: Parse records from the input files.
        parser = self.engine.get_parser(self._resolve_parser_name(parser_name))
        records: List[Dict[str, Any]] = []
        for file_path in resolved_inputs:
            parsed_records = parser.parse(file_path) or []
            for record in parsed_records:
                if isinstance(record, dict) and 'log_file' not in record:
                    record['log_file'] = file_path
            records.extend(parsed_records)

        # Step 2: Run the selected detectors.
        findings: List[Dict[str, Any]] = []
        detectors_run = 0
        for detector_name in detector_names:
            detector = self.engine.get_detector(self._resolve_detector_name(detector_name))
            detector_findings = detector.detect(records) or []
            findings.extend(detector_findings)
            detectors_run += 1

        # Step 3: Correlate findings when multiple detectors point to the same source.
        correlations = self._correlate_findings(findings)

        # Step 4: Build and write the report.
        report_path = output_file or 'report.json'
        
        # Check if user wants text format or JSON format.
        if report_path.lower().endswith('.txt'):
            # Generate and write text report.
            text_report = self.report_generator.generate_text_report(records, findings, correlations)
            write_text(report_path, text_report)
        else:
            # Generate and write JSON report (default).
            report = self.report_generator.generate_report(records, findings, correlations)
            write_json(report_path, report)

        return {
            'redact': {
                'records_processed': len(records),
                'files_processed': len(resolved_inputs),
            },
            'assess': {
                'total_findings': len(findings),
                'detectors_run': detectors_run,
            },
            'integrate': {
                'correlations_identified': len(correlations),
            },
            'deploy': {
                'output_file': report_path,
            },
        }

    def _expand_input_paths(self, input_paths: List[str]) -> List[str]:
        # Accept both files and folders, then return a unique file list.
        resolved_files: List[str] = []

        for input_path in input_paths:
            if os.path.isdir(input_path):
                for root, _, filenames in os.walk(input_path):
                    for filename in sorted(filenames):
                        resolved_files.append(os.path.join(root, filename))
            elif os.path.isfile(input_path):
                resolved_files.append(input_path)

        unique_files: List[str] = []
        seen = set()
        for file_path in resolved_files:
            normalized = os.path.normcase(os.path.normpath(file_path))
            if normalized in seen:
                continue
            seen.add(normalized)
            unique_files.append(file_path)

        if not unique_files:
            raise ValueError('No valid input files found. Provide a file path or folder containing log files.')

        return unique_files

    def _resolve_parser_name(self, parser_name: str) -> str:
        # Support short parser names (e.g., windows_event_log -> windows_event_log_parser).
        if parser_name in self.engine.parsers:
            return parser_name

        candidates = [
            f"{parser_name}_parser",
            f"{parser_name}_log_parser",
        ]
        for candidate in candidates:
            if candidate in self.engine.parsers:
                return candidate

        return parser_name

    def _resolve_detector_name(self, detector_name: str) -> str:
        # Support short detector names (e.g., windows_event -> windows_event_detector).
        if detector_name in self.engine.detectors:
            return detector_name

        candidate = f"{detector_name}_detector"
        if candidate in self.engine.detectors:
            return candidate

        return detector_name

    def _correlate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Simple correlation by source IP across different detectors.
        grouped_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            source_ip = finding.get('source_ip')
            if not source_ip:
                continue
            grouped_by_ip.setdefault(source_ip, []).append(finding)

        correlations: List[Dict[str, Any]] = []
        for source_ip, ip_findings in grouped_by_ip.items():
            if len(ip_findings) < 2:
                continue

            detectors = sorted({f.get('detector', 'unknown') for f in ip_findings})
            if len(detectors) < 2:
                continue

            correlations.append({
                'id': f"corr_{source_ip}",
                'type': 'multi_detector_source_ip',
                'source_ip': source_ip,
                'description': (
                    f"Multiple detectors flagged activity from {source_ip}: "
                    f"{', '.join(detectors)}"
                ),
                'related_finding_ids': [f.get('id') for f in ip_findings if f.get('id')],
                'detectors': detectors,
                'severity': 'high',
            })

        return correlations
