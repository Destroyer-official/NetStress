"""
Tests for mutation engine and reporting modules
"""

import pytest
import time
from unittest.mock import Mock


class TestMutationEngine:
    """Tests for mutation engine"""
    
    def test_mutation_config_creation(self):
        """Test mutation config"""
        from core.attacks.mutation_engine import MutationConfig
        
        config = MutationConfig(mutation_rate=0.2, population_size=100)
        assert config.mutation_rate == 0.2
        assert config.population_size == 100
        
    def test_individual_creation(self):
        """Test individual creation"""
        from core.attacks.mutation_engine import Individual
        
        ind = Individual(payload=b"test payload")
        assert ind.payload == b"test payload"
        assert ind.fitness == 0.0
        
    def test_entropy_fitness(self):
        """Test entropy fitness function"""
        from core.attacks.mutation_engine import EntropyFitness
        
        fitness = EntropyFitness()
        
        # High entropy (random bytes)
        high_entropy = bytes(range(256))
        score1 = fitness.evaluate(high_entropy)
        
        # Low entropy (repeated bytes)
        low_entropy = b'\x00' * 256
        score2 = fitness.evaluate(low_entropy)
        
        assert score1 > score2
        
    def test_unique_fitness(self):
        """Test unique fitness function"""
        from core.attacks.mutation_engine import UniqueFitness
        
        fitness = UniqueFitness()
        
        # First evaluation - unique payload
        score1 = fitness.evaluate(b"unique payload 1")
        
        # Same payload should be penalized (returns 0.1 for duplicates)
        score2 = fitness.evaluate(b"unique payload 1")
        
        # Duplicate penalty is 0.1
        assert score2 == 0.1
        
    def test_size_fitness(self):
        """Test size fitness function"""
        from core.attacks.mutation_engine import SizeFitness
        
        fitness = SizeFitness(target_size=100)
        
        # Exact size
        score1 = fitness.evaluate(b'x' * 100)
        
        # Different size
        score2 = fitness.evaluate(b'x' * 50)
        
        assert score1 > score2
        
    def test_composite_fitness(self):
        """Test composite fitness function"""
        from core.attacks.mutation_engine import CompositeFitness, EntropyFitness, SizeFitness
        
        fitness = CompositeFitness([
            (EntropyFitness(), 0.5),
            (SizeFitness(target_size=100), 0.5),
        ])
        
        score = fitness.evaluate(bytes(range(100)))
        assert 0 <= score <= 1
        
    def test_bit_flip_mutation(self):
        """Test bit flip mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'\x00' * 10
        mutated = MutationOperator.bit_flip(original, count=1)
        
        assert mutated != original
        assert len(mutated) == len(original)
        
    def test_byte_swap_mutation(self):
        """Test byte swap mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = bytes(range(10))
        mutated = MutationOperator.byte_swap(original)
        
        # Same bytes, possibly different order
        assert sorted(mutated) == sorted(original)
        
    def test_byte_insert_mutation(self):
        """Test byte insert mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'test'
        mutated = MutationOperator.byte_insert(original, max_insert=5)
        
        assert len(mutated) > len(original)
        
    def test_byte_delete_mutation(self):
        """Test byte delete mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'test data here'
        mutated = MutationOperator.byte_delete(original, max_delete=3)
        
        assert len(mutated) < len(original)
        
    def test_block_shuffle_mutation(self):
        """Test block shuffle mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = bytes(range(16))
        mutated = MutationOperator.block_shuffle(original, block_size=4)
        
        assert len(mutated) == len(original)
        
    def test_arithmetic_mutation(self):
        """Test arithmetic mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'\x10' * 10
        mutated = MutationOperator.arithmetic(original)
        
        assert len(mutated) == len(original)
        
    def test_dictionary_replace_mutation(self):
        """Test dictionary replace mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'\x00' * 10
        mutated = MutationOperator.dictionary_replace(original)
        
        assert len(mutated) == len(original)
        
    def test_havoc_mutation(self):
        """Test havoc mutation"""
        from core.attacks.mutation_engine import MutationOperator
        
        original = b'test payload data'
        mutated = MutationOperator.havoc(original, iterations=3)
        
        # Havoc should change the payload
        assert mutated != original or len(mutated) != len(original)
        
    def test_single_point_crossover(self):
        """Test single point crossover"""
        from core.attacks.mutation_engine import CrossoverOperator
        
        parent1 = b'AAAAAAAAAA'
        parent2 = b'BBBBBBBBBB'
        
        child1, child2 = CrossoverOperator.single_point(parent1, parent2)
        
        assert len(child1) == len(parent1)
        assert len(child2) == len(parent2)
        
    def test_two_point_crossover(self):
        """Test two point crossover"""
        from core.attacks.mutation_engine import CrossoverOperator
        
        parent1 = b'AAAAAAAAAA'
        parent2 = b'BBBBBBBBBB'
        
        child1, child2 = CrossoverOperator.two_point(parent1, parent2)
        
        assert len(child1) == len(parent1)
        
    def test_uniform_crossover(self):
        """Test uniform crossover"""
        from core.attacks.mutation_engine import CrossoverOperator
        
        parent1 = b'AAAAAAAAAA'
        parent2 = b'BBBBBBBBBB'
        
        child1, child2 = CrossoverOperator.uniform(parent1, parent2)
        
        assert len(child1) >= min(len(parent1), len(parent2))
        
    def test_mutation_engine_creation(self):
        """Test mutation engine creation"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        engine = MutationEngine(MutationConfig())
        assert engine.generation == 0
        
    def test_mutation_engine_initialize(self):
        """Test mutation engine initialization"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        config = MutationConfig(population_size=10)
        engine = MutationEngine(config)
        engine.initialize()
        
        assert len(engine.population) == 10
        
    def test_mutation_engine_initialize_with_seeds(self):
        """Test mutation engine initialization with seeds"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        config = MutationConfig(population_size=10)
        engine = MutationEngine(config)
        
        seeds = [b'seed1', b'seed2', b'seed3']
        engine.initialize(seed_payloads=seeds)
        
        assert len(engine.population) == 10
        
    def test_mutation_engine_evolve(self):
        """Test mutation engine evolution"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        config = MutationConfig(population_size=10, max_generations=5)
        engine = MutationEngine(config)
        engine.initialize()
        
        best = engine.evolve(generations=5)
        
        assert engine.generation == 5
        assert best is not None
        
    def test_mutation_engine_get_best_payloads(self):
        """Test getting best payloads"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        config = MutationConfig(population_size=20)
        engine = MutationEngine(config)
        engine.initialize()
        engine.evolve(generations=3)
        
        best = engine.get_best_payloads(count=5)
        
        assert len(best) == 5
        assert all(isinstance(p, bytes) for p in best)
        
    def test_mutation_engine_stats(self):
        """Test mutation engine statistics"""
        from core.attacks.mutation_engine import MutationEngine, MutationConfig
        
        config = MutationConfig(population_size=10)
        engine = MutationEngine(config)
        engine.initialize()
        engine.evolve(generations=3)
        
        stats = engine.get_stats()
        
        assert 'generation' in stats
        assert 'best_fitness' in stats
        assert 'avg_fitness' in stats
        
    def test_adaptive_mutation_engine(self):
        """Test adaptive mutation engine"""
        from core.attacks.mutation_engine import AdaptiveMutationEngine, MutationConfig
        
        config = MutationConfig(population_size=10)
        engine = AdaptiveMutationEngine(config)
        engine.initialize()
        
        initial_rate = engine.config.mutation_rate
        engine.evolve(generations=20)
        
        # Rate should have adapted
        assert engine.generation == 20


class TestAdvancedReporting:
    """Tests for advanced reporting module"""
    
    def test_attack_metrics_creation(self):
        """Test attack metrics creation"""
        from core.reporting.advanced_reports import AttackMetrics
        
        metrics = AttackMetrics(
            requests_sent=1000,
            requests_successful=950,
            requests_failed=50
        )
        
        assert metrics.requests_sent == 1000
        
    def test_attack_metrics_calculate_derived(self):
        """Test derived metrics calculation"""
        from core.reporting.advanced_reports import AttackMetrics
        
        metrics = AttackMetrics(
            start_time=0,
            end_time=10,
            requests_sent=1000,
            requests_successful=900,
            requests_failed=100,
            bytes_sent=1000000
        )
        metrics.calculate_derived()
        
        assert metrics.duration == 10
        assert metrics.requests_per_second == 100
        assert metrics.error_rate == 0.1
        
    def test_target_metrics_creation(self):
        """Test target metrics creation"""
        from core.reporting.advanced_reports import TargetMetrics
        
        metrics = TargetMetrics(
            initial_response_time_ms=10,
            final_response_time_ms=100
        )
        metrics.calculate_derived()
        
        assert metrics.response_time_increase == 900  # 900% increase
        
    def test_attack_report_creation(self):
        """Test attack report creation"""
        from core.reporting.advanced_reports import AttackReport
        
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        assert report.report_id == "test123"
        assert report.attack_type == "HTTP Flood"
        
    def test_attack_report_to_dict(self):
        """Test report to dictionary conversion"""
        from core.reporting.advanced_reports import AttackReport
        
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        data = report.to_dict()
        
        assert data['report_id'] == "test123"
        assert 'attack_metrics' in data
        
    def test_metrics_collector_creation(self):
        """Test metrics collector creation"""
        from core.reporting.advanced_reports import MetricsCollector
        
        collector = MetricsCollector()
        collector.start()
        
        assert collector._running is True
        
    def test_metrics_collector_record(self):
        """Test recording metrics"""
        from core.reporting.advanced_reports import MetricsCollector
        
        collector = MetricsCollector()
        collector.start()
        
        collector.record_request(
            response_time_ms=50,
            bytes_sent=1000,
            status_code=200
        )
        
        metrics = collector.get_current_metrics()
        
        assert metrics['total_requests'] == 1
        assert metrics['avg_response_time_ms'] == 50
        
    def test_effectiveness_analyzer(self):
        """Test effectiveness analyzer"""
        from core.reporting.advanced_reports import (
            EffectivenessAnalyzer, AttackMetrics, TargetMetrics
        )
        
        analyzer = EffectivenessAnalyzer()
        analyzer.set_baseline(response_time_ms=10)
        
        attack_metrics = AttackMetrics(
            duration=60,
            requests_sent=10000,
            error_rate=0.05
        )
        
        target_metrics = TargetMetrics(
            initial_response_time_ms=10,
            final_response_time_ms=100,
            availability_drop=20,
            status_codes={200: 8000, 500: 2000}
        )
        
        score = analyzer.calculate_effectiveness(attack_metrics, target_metrics)
        
        assert 0 <= score <= 100
        
    def test_effectiveness_assessment(self):
        """Test effectiveness assessment generation"""
        from core.reporting.advanced_reports import EffectivenessAnalyzer
        
        analyzer = EffectivenessAnalyzer()
        
        assert "Highly Effective" in analyzer.generate_assessment(85)
        assert "Effective" in analyzer.generate_assessment(65)
        assert "Ineffective" in analyzer.generate_assessment(10)
        
    def test_report_generator_text(self):
        """Test text report generation"""
        from core.reporting.advanced_reports import (
            ReportGenerator, AttackReport, ReportFormat
        )
        
        generator = ReportGenerator()
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        text = generator.generate(report, ReportFormat.TEXT)
        
        assert "ATTACK REPORT" in text
        assert "test123" in text
        
    def test_report_generator_json(self):
        """Test JSON report generation"""
        from core.reporting.advanced_reports import (
            ReportGenerator, AttackReport, ReportFormat
        )
        import json
        
        generator = ReportGenerator()
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        json_str = generator.generate(report, ReportFormat.JSON)
        data = json.loads(json_str)
        
        assert data['report_id'] == "test123"
        
    def test_report_generator_html(self):
        """Test HTML report generation"""
        from core.reporting.advanced_reports import (
            ReportGenerator, AttackReport, ReportFormat
        )
        
        generator = ReportGenerator()
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        html = generator.generate(report, ReportFormat.HTML)
        
        assert "<html>" in html
        assert "test123" in html
        
    def test_report_generator_csv(self):
        """Test CSV report generation"""
        from core.reporting.advanced_reports import (
            ReportGenerator, AttackReport, ReportFormat
        )
        
        generator = ReportGenerator()
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        csv = generator.generate(report, ReportFormat.CSV)
        
        assert "report_id" in csv
        assert "test123" in csv
        
    def test_report_generator_markdown(self):
        """Test Markdown report generation"""
        from core.reporting.advanced_reports import (
            ReportGenerator, AttackReport, ReportFormat
        )
        
        generator = ReportGenerator()
        report = AttackReport(
            report_id="test123",
            attack_type="HTTP Flood",
            target="192.168.1.100",
            port=80
        )
        
        md = generator.generate(report, ReportFormat.MARKDOWN)
        
        assert "# Attack Report" in md
        assert "test123" in md
        
    def test_report_manager_creation(self):
        """Test report manager creation"""
        from core.reporting.advanced_reports import ReportManager
        
        manager = ReportManager()
        assert manager is not None
        
    def test_report_manager_start_attack(self):
        """Test starting attack tracking"""
        from core.reporting.advanced_reports import ReportManager
        
        manager = ReportManager()
        report_id = manager.start_attack("HTTP Flood", "192.168.1.100", 80)
        
        assert report_id is not None
        assert len(report_id) == 12
        
    def test_report_manager_record_and_end(self):
        """Test recording and ending attack"""
        from core.reporting.advanced_reports import ReportManager
        
        manager = ReportManager()
        report_id = manager.start_attack("HTTP Flood", "192.168.1.100", 80)
        
        # Record some requests
        for _ in range(10):
            manager.record_request(
                response_time_ms=50,
                bytes_sent=1000,
                status_code=200
            )
            
        report = manager.end_attack(summary="Test completed")
        
        assert report is not None
        assert report.attack_metrics.requests_sent == 10
        
    def test_report_manager_export(self):
        """Test exporting report"""
        from core.reporting.advanced_reports import ReportManager, ReportFormat
        
        manager = ReportManager()
        report_id = manager.start_attack("HTTP Flood", "192.168.1.100", 80)
        manager.record_request(response_time_ms=50, bytes_sent=1000)
        manager.end_attack()
        
        text = manager.export_report(report_id, ReportFormat.TEXT)
        
        assert "ATTACK REPORT" in text


class TestModuleImports:
    """Test module imports"""
    
    def test_import_mutation_engine(self):
        """Test mutation engine imports"""
        from core.attacks import (
            MutationType, MutationConfig, Individual, FitnessFunction,
            EntropyFitness, UniqueFitness, SizeFitness, CompositeFitness,
            MutationOperator, CrossoverOperator, MutationEngine, AdaptiveMutationEngine
        )
        
    def test_import_reporting(self):
        """Test reporting imports"""
        from core.reporting import (
            ReportFormat, AttackMetrics, TargetMetrics, AttackReport,
            MetricsCollector, EffectivenessAnalyzer, ReportGenerator, ReportManager
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
