"""
Advanced Reporting Module

Comprehensive attack reporting and analysis:
- Real-time metrics collection
- Attack effectiveness analysis
- Target response analysis
- Export to multiple formats
"""

import time
import json
import statistics
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum
from collections import deque
import logging

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    TEXT = "text"
    HTML = "html"
    CSV = "csv"
    MARKDOWN = "markdown"


@dataclass
class AttackMetrics:
    """Attack metrics data"""
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    requests_sent: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    requests_per_second: float = 0.0
    bandwidth_mbps: float = 0.0
    error_rate: float = 0.0
    
    def calculate_derived(self):
        """Calculate derived metrics"""
        self.duration = self.end_time - self.start_time if self.end_time > self.start_time else 0
        
        if self.duration > 0:
            self.requests_per_second = self.requests_sent / self.duration
            self.bandwidth_mbps = (self.bytes_sent * 8) / (self.duration * 1_000_000)
            
        total = self.requests_successful + self.requests_failed
        if total > 0:
            self.error_rate = self.requests_failed / total


@dataclass
class TargetMetrics:
    """Target response metrics"""
    initial_response_time_ms: float = 0.0
    final_response_time_ms: float = 0.0
    response_time_increase: float = 0.0
    availability_start: float = 1.0
    availability_end: float = 1.0
    availability_drop: float = 0.0
    status_codes: Dict[int, int] = field(default_factory=dict)
    error_types: Dict[str, int] = field(default_factory=dict)
    
    def calculate_derived(self):
        """Calculate derived metrics"""
        if self.initial_response_time_ms > 0:
            self.response_time_increase = (
                (self.final_response_time_ms - self.initial_response_time_ms) 
                / self.initial_response_time_ms * 100
            )
        self.availability_drop = (self.availability_start - self.availability_end) * 100


@dataclass
class AttackReport:
    """Complete attack report"""
    report_id: str = ""
    attack_type: str = ""
    target: str = ""
    port: int = 0
    timestamp: float = field(default_factory=time.time)
    attack_metrics: AttackMetrics = field(default_factory=AttackMetrics)
    target_metrics: TargetMetrics = field(default_factory=TargetMetrics)
    configuration: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    effectiveness_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'attack_type': self.attack_type,
            'target': f"{self.target}:{self.port}",
            'timestamp': self.timestamp,
            'attack_metrics': asdict(self.attack_metrics),
            'target_metrics': asdict(self.target_metrics),
            'configuration': self.configuration,
            'events': self.events,
            'summary': self.summary,
            'effectiveness_score': self.effectiveness_score,
        }


class MetricsCollector:
    """
    Real-time Metrics Collector
    
    Collects and aggregates attack metrics in real-time.
    """
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self._response_times: deque = deque(maxlen=window_size)
        self._request_times: deque = deque(maxlen=window_size)
        self._errors: deque = deque(maxlen=window_size)
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._status_codes: Dict[int, int] = {}
        self._start_time: float = 0.0
        self._running = False
        
    def start(self):
        """Start collecting"""
        self._start_time = time.time()
        self._running = True
        
    def stop(self):
        """Stop collecting"""
        self._running = False
        
    def record_request(self, response_time_ms: float, bytes_sent: int = 0,
                      bytes_received: int = 0, status_code: int = 200,
                      error: bool = False):
        """Record a request"""
        current_time = time.time()
        
        self._response_times.append(response_time_ms)
        self._request_times.append(current_time)
        self._errors.append(1 if error else 0)
        self._bytes_sent += bytes_sent
        self._bytes_received += bytes_received
        self._status_codes[status_code] = self._status_codes.get(status_code, 0) + 1
        
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot"""
        if not self._response_times:
            return {}
            
        current_time = time.time()
        elapsed = current_time - self._start_time if self._start_time > 0 else 0
        
        # Calculate RPS from recent requests
        recent_requests = [t for t in self._request_times if t > current_time - 1]
        current_rps = len(recent_requests)
        
        return {
            'elapsed_seconds': elapsed,
            'total_requests': len(self._request_times),
            'current_rps': current_rps,
            'avg_response_time_ms': statistics.mean(self._response_times),
            'min_response_time_ms': min(self._response_times),
            'max_response_time_ms': max(self._response_times),
            'p50_response_time_ms': statistics.median(self._response_times),
            'p95_response_time_ms': self._percentile(95),
            'p99_response_time_ms': self._percentile(99),
            'error_rate': sum(self._errors) / len(self._errors) if self._errors else 0,
            'bytes_sent': self._bytes_sent,
            'bytes_received': self._bytes_received,
            'bandwidth_mbps': (self._bytes_sent * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0,
        }
        
    def _percentile(self, p: int) -> float:
        """Calculate percentile"""
        if not self._response_times:
            return 0.0
        sorted_times = sorted(self._response_times)
        index = int(len(sorted_times) * p / 100)
        return sorted_times[min(index, len(sorted_times) - 1)]
        
    def get_attack_metrics(self) -> AttackMetrics:
        """Get complete attack metrics"""
        metrics = AttackMetrics(
            start_time=self._start_time,
            end_time=time.time(),
            requests_sent=len(self._request_times),
            requests_successful=len(self._errors) - sum(self._errors),
            requests_failed=sum(self._errors),
            bytes_sent=self._bytes_sent,
            bytes_received=self._bytes_received,
        )
        
        if self._response_times:
            metrics.avg_response_time_ms = statistics.mean(self._response_times)
            metrics.min_response_time_ms = min(self._response_times)
            metrics.max_response_time_ms = max(self._response_times)
            
        metrics.calculate_derived()
        return metrics


class EffectivenessAnalyzer:
    """
    Attack Effectiveness Analyzer
    
    Analyzes attack effectiveness based on target response.
    """
    
    def __init__(self):
        self._baseline_response_time: Optional[float] = None
        self._baseline_availability: float = 1.0
        
    def set_baseline(self, response_time_ms: float, availability: float = 1.0):
        """Set baseline metrics"""
        self._baseline_response_time = response_time_ms
        self._baseline_availability = availability
        
    def calculate_effectiveness(self, attack_metrics: AttackMetrics,
                               target_metrics: TargetMetrics) -> float:
        """
        Calculate attack effectiveness score (0-100).
        
        Factors:
        - Response time degradation
        - Availability reduction
        - Error rate induced
        - Sustained impact
        """
        score = 0.0
        
        # Response time degradation (0-30 points)
        if self._baseline_response_time and self._baseline_response_time > 0:
            degradation = target_metrics.final_response_time_ms / self._baseline_response_time
            score += min(30, (degradation - 1) * 10)
            
        # Availability reduction (0-40 points)
        availability_drop = target_metrics.availability_drop
        score += min(40, availability_drop * 0.4)
        
        # Error rate (0-20 points)
        error_rate = attack_metrics.error_rate
        # Lower error rate on attacker side is better (means target is accepting)
        # But high 5xx errors on target is good
        server_errors = sum(v for k, v in target_metrics.status_codes.items() if 500 <= k < 600)
        total_responses = sum(target_metrics.status_codes.values())
        if total_responses > 0:
            server_error_rate = server_errors / total_responses
            score += min(20, server_error_rate * 100)
            
        # Sustained impact (0-10 points)
        if attack_metrics.duration > 60:
            score += min(10, attack_metrics.duration / 60)
            
        return min(100, max(0, score))
        
    def generate_assessment(self, score: float) -> str:
        """Generate effectiveness assessment"""
        if score >= 80:
            return "Highly Effective - Target severely impacted"
        elif score >= 60:
            return "Effective - Significant target degradation"
        elif score >= 40:
            return "Moderately Effective - Noticeable impact"
        elif score >= 20:
            return "Limited Effectiveness - Minor impact"
        else:
            return "Ineffective - Minimal or no impact"


class ReportGenerator:
    """
    Report Generator
    
    Generates reports in various formats.
    """
    
    def __init__(self):
        self.analyzer = EffectivenessAnalyzer()
        
    def generate(self, report: AttackReport, format: ReportFormat = ReportFormat.TEXT) -> str:
        """Generate report in specified format"""
        if format == ReportFormat.JSON:
            return self._generate_json(report)
        elif format == ReportFormat.TEXT:
            return self._generate_text(report)
        elif format == ReportFormat.HTML:
            return self._generate_html(report)
        elif format == ReportFormat.CSV:
            return self._generate_csv(report)
        elif format == ReportFormat.MARKDOWN:
            return self._generate_markdown(report)
        else:
            return self._generate_text(report)
            
    def _generate_json(self, report: AttackReport) -> str:
        """Generate JSON report"""
        return json.dumps(report.to_dict(), indent=2)
        
    def _generate_text(self, report: AttackReport) -> str:
        """Generate text report"""
        lines = [
            "=" * 60,
            "ATTACK REPORT",
            "=" * 60,
            f"Report ID: {report.report_id}",
            f"Attack Type: {report.attack_type}",
            f"Target: {report.target}:{report.port}",
            f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.timestamp))}",
            "",
            "ATTACK METRICS",
            "-" * 40,
            f"Duration: {report.attack_metrics.duration:.2f}s",
            f"Requests Sent: {report.attack_metrics.requests_sent:,}",
            f"Requests/Second: {report.attack_metrics.requests_per_second:.2f}",
            f"Bandwidth: {report.attack_metrics.bandwidth_mbps:.2f} Mbps",
            f"Error Rate: {report.attack_metrics.error_rate * 100:.2f}%",
            f"Avg Response Time: {report.attack_metrics.avg_response_time_ms:.2f}ms",
            "",
            "TARGET METRICS",
            "-" * 40,
            f"Initial Response Time: {report.target_metrics.initial_response_time_ms:.2f}ms",
            f"Final Response Time: {report.target_metrics.final_response_time_ms:.2f}ms",
            f"Response Time Increase: {report.target_metrics.response_time_increase:.1f}%",
            f"Availability Drop: {report.target_metrics.availability_drop:.1f}%",
            "",
            "EFFECTIVENESS",
            "-" * 40,
            f"Score: {report.effectiveness_score:.1f}/100",
            f"Assessment: {self.analyzer.generate_assessment(report.effectiveness_score)}",
            "",
            "SUMMARY",
            "-" * 40,
            report.summary or "No summary available",
            "=" * 60,
        ]
        return "\n".join(lines)
        
    def _generate_html(self, report: AttackReport) -> str:
        """Generate HTML report"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Attack Report - {report.report_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px; padding: 10px; background: white; border-radius: 3px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .metric-label {{ font-size: 12px; color: #666; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .score-high {{ color: #dc3545; }}
        .score-medium {{ color: #ffc107; }}
        .score-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <h1>Attack Report</h1>
    <p><strong>ID:</strong> {report.report_id}</p>
    <p><strong>Target:</strong> {report.target}:{report.port}</p>
    <p><strong>Type:</strong> {report.attack_type}</p>
    
    <div class="section">
        <h2>Attack Metrics</h2>
        <div class="metric">
            <div class="metric-value">{report.attack_metrics.requests_sent:,}</div>
            <div class="metric-label">Requests Sent</div>
        </div>
        <div class="metric">
            <div class="metric-value">{report.attack_metrics.requests_per_second:.0f}</div>
            <div class="metric-label">Requests/Second</div>
        </div>
        <div class="metric">
            <div class="metric-value">{report.attack_metrics.bandwidth_mbps:.2f}</div>
            <div class="metric-label">Bandwidth (Mbps)</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Effectiveness Score</h2>
        <div class="score {'score-high' if report.effectiveness_score >= 60 else 'score-medium' if report.effectiveness_score >= 30 else 'score-low'}">
            {report.effectiveness_score:.0f}/100
        </div>
        <p>{self.analyzer.generate_assessment(report.effectiveness_score)}</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p>{report.summary or 'No summary available'}</p>
    </div>
</body>
</html>"""
        
    def _generate_csv(self, report: AttackReport) -> str:
        """Generate CSV report"""
        headers = [
            "report_id", "attack_type", "target", "port", "timestamp",
            "duration", "requests_sent", "rps", "bandwidth_mbps", "error_rate",
            "effectiveness_score"
        ]
        values = [
            report.report_id,
            report.attack_type,
            report.target,
            str(report.port),
            str(report.timestamp),
            f"{report.attack_metrics.duration:.2f}",
            str(report.attack_metrics.requests_sent),
            f"{report.attack_metrics.requests_per_second:.2f}",
            f"{report.attack_metrics.bandwidth_mbps:.2f}",
            f"{report.attack_metrics.error_rate:.4f}",
            f"{report.effectiveness_score:.1f}"
        ]
        return ",".join(headers) + "\n" + ",".join(values)
        
    def _generate_markdown(self, report: AttackReport) -> str:
        """Generate Markdown report"""
        return f"""# Attack Report

**Report ID:** {report.report_id}  
**Attack Type:** {report.attack_type}  
**Target:** {report.target}:{report.port}  
**Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.timestamp))}

## Attack Metrics

| Metric | Value |
|--------|-------|
| Duration | {report.attack_metrics.duration:.2f}s |
| Requests Sent | {report.attack_metrics.requests_sent:,} |
| Requests/Second | {report.attack_metrics.requests_per_second:.2f} |
| Bandwidth | {report.attack_metrics.bandwidth_mbps:.2f} Mbps |
| Error Rate | {report.attack_metrics.error_rate * 100:.2f}% |

## Target Metrics

| Metric | Value |
|--------|-------|
| Initial Response Time | {report.target_metrics.initial_response_time_ms:.2f}ms |
| Final Response Time | {report.target_metrics.final_response_time_ms:.2f}ms |
| Response Time Increase | {report.target_metrics.response_time_increase:.1f}% |
| Availability Drop | {report.target_metrics.availability_drop:.1f}% |

## Effectiveness

**Score:** {report.effectiveness_score:.1f}/100

**Assessment:** {self.analyzer.generate_assessment(report.effectiveness_score)}

## Summary

{report.summary or 'No summary available'}
"""


class ReportManager:
    """
    Report Manager
    
    Manages report generation and storage.
    """
    
    def __init__(self):
        self.collector = MetricsCollector()
        self.analyzer = EffectivenessAnalyzer()
        self.generator = ReportGenerator()
        self._reports: List[AttackReport] = []
        self._current_report: Optional[AttackReport] = None
        
    def start_attack(self, attack_type: str, target: str, port: int,
                    config: Dict[str, Any] = None):
        """Start tracking a new attack"""
        import hashlib
        
        report_id = hashlib.md5(f"{target}:{port}:{time.time()}".encode()).hexdigest()[:12]
        
        self._current_report = AttackReport(
            report_id=report_id,
            attack_type=attack_type,
            target=target,
            port=port,
            configuration=config or {}
        )
        
        self.collector = MetricsCollector()
        self.collector.start()
        
        return report_id
        
    def record_request(self, response_time_ms: float, bytes_sent: int = 0,
                      bytes_received: int = 0, status_code: int = 200,
                      error: bool = False):
        """Record a request during attack"""
        self.collector.record_request(
            response_time_ms, bytes_sent, bytes_received, status_code, error
        )
        
    def record_event(self, event_type: str, description: str, data: Dict = None):
        """Record an event during attack"""
        if self._current_report:
            self._current_report.events.append({
                'timestamp': time.time(),
                'type': event_type,
                'description': description,
                'data': data or {}
            })
            
    def end_attack(self, summary: str = None) -> AttackReport:
        """End attack and generate report"""
        self.collector.stop()
        
        if not self._current_report:
            return None
            
        # Populate metrics
        self._current_report.attack_metrics = self.collector.get_attack_metrics()
        
        # Calculate effectiveness
        self._current_report.effectiveness_score = self.analyzer.calculate_effectiveness(
            self._current_report.attack_metrics,
            self._current_report.target_metrics
        )
        
        self._current_report.summary = summary or self._generate_summary()
        
        self._reports.append(self._current_report)
        report = self._current_report
        self._current_report = None
        
        return report
        
    def _generate_summary(self) -> str:
        """Generate automatic summary"""
        if not self._current_report:
            return ""
            
        metrics = self._current_report.attack_metrics
        score = self._current_report.effectiveness_score
        
        return (
            f"Attack completed in {metrics.duration:.1f}s. "
            f"Sent {metrics.requests_sent:,} requests at {metrics.requests_per_second:.0f} RPS. "
            f"Effectiveness score: {score:.0f}/100."
        )
        
    def get_report(self, report_id: str) -> Optional[AttackReport]:
        """Get report by ID"""
        for report in self._reports:
            if report.report_id == report_id:
                return report
        return None
        
    def export_report(self, report_id: str, format: ReportFormat = ReportFormat.TEXT) -> str:
        """Export report in specified format"""
        report = self.get_report(report_id)
        if report:
            return self.generator.generate(report, format)
        return ""
        
    def get_all_reports(self) -> List[AttackReport]:
        """Get all reports"""
        return self._reports.copy()
