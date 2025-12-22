"""
Property-Based Tests for Timing Distribution Accuracy

Tests Property 5: Timing Distribution Accuracy
Validates: Requirements 16.5, 23.2

**Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
**Validates: Requirements 16.5, 23.2**
"""

import pytest
import sys
import os
import math
import statistics
from typing import List

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from hypothesis import given, strategies as st, settings, assume
from scipy import stats as scipy_stats
import numpy as np

# Import timing modules
try:
    from core.evasion.timing_patterns import (
        TimingController,
        TimingConfig,
        TimingPattern
    )
    TIMING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import timing modules: {e}")
    TIMING_AVAILABLE = False


class TestTimingDistributionProperty:
    """
    Property-based tests for timing distribution accuracy.
    
    Validates that timing patterns follow their expected statistical distributions.
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        if not TIMING_AVAILABLE:
            pytest.skip("Timing modules not available")
    
    @given(
        poisson_lambda=st.floats(min_value=10.0, max_value=1000.0),
        num_samples=st.integers(min_value=100, max_value=500)
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_5_poisson_timing_distribution_accuracy(self, poisson_lambda, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any Poisson timing configuration with rate λ,
        the generated inter-arrival times SHALL follow an exponential 
        distribution with mean 1/λ and variance 1/λ² within statistical tolerance.
        
        This validates that:
        1. The timing follows the correct mathematical distribution
        2. The mean matches the expected value (1/λ)
        3. The variance matches the expected value (1/λ²)
        4. The distribution passes statistical tests (Kolmogorov-Smirnov)
        """
        # Create Poisson timing controller
        config = TimingConfig(
            pattern=TimingPattern.POISSON,
            poisson_lambda=poisson_lambda,
            min_interval=0.0,
            max_interval=10.0
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = []
        for _ in range(num_samples):
            interval = controller.get_interval()
            samples.append(interval)
        
        # Statistical validation
        sample_mean = statistics.mean(samples)
        sample_variance = statistics.variance(samples) if len(samples) > 1 else 0
        
        # Expected values for exponential distribution
        expected_mean = 1.0 / poisson_lambda
        expected_variance = 1.0 / (poisson_lambda ** 2)
        
        # Test 1: Mean should be close to expected
        # Use statistical confidence interval instead of fixed percentage
        # For exponential distribution, standard error of mean = mean / sqrt(n)
        se_mean = expected_mean / math.sqrt(num_samples)
        # 95% confidence interval is approximately ±2 standard errors
        lower_bound = expected_mean - 2.5 * se_mean
        upper_bound = expected_mean + 2.5 * se_mean
        
        assert lower_bound <= sample_mean <= upper_bound, (
            f"Poisson timing mean {sample_mean:.6f} outside 95% confidence interval "
            f"[{lower_bound:.6f}, {upper_bound:.6f}] for expected {expected_mean:.6f} "
            f"(lambda: {poisson_lambda}, n: {num_samples})"
        )
        
        # Test 2: Variance should be close to expected
        # For exponential distribution, variance of sample variance is approximately 2*var^2/(n-1)
        se_variance = math.sqrt(2 * expected_variance ** 2 / (num_samples - 1))
        # Use wider confidence interval for variance (it has higher variation)
        lower_bound_var = max(0, expected_variance - 3 * se_variance)
        upper_bound_var = expected_variance + 3 * se_variance
        
        assert lower_bound_var <= sample_variance <= upper_bound_var, (
            f"Poisson timing variance {sample_variance:.6f} outside confidence interval "
            f"[{lower_bound_var:.6f}, {upper_bound_var:.6f}] for expected {expected_variance:.6f} "
            f"(lambda: {poisson_lambda}, n: {num_samples})"
        )
        
        # Test 3: Kolmogorov-Smirnov test for exponential distribution
        # This tests if the samples come from an exponential distribution
        # Skip KS test for very small lambda values with small samples as they're prone to edge effects
        if poisson_lambda >= 20.0 or num_samples >= 200:
            ks_statistic, p_value = scipy_stats.kstest(
                samples,
                lambda x: scipy_stats.expon.cdf(x, scale=expected_mean)
            )
            
            # p-value > 0.05 means we cannot reject the hypothesis that samples follow exponential distribution
            # For property testing, we use a low threshold (0.001) to catch real problems
            # while allowing for statistical variation in small samples
            assert p_value > 0.001, (
                f"Poisson timing failed Kolmogorov-Smirnov test for exponential distribution "
                f"(KS statistic: {ks_statistic:.4f}, p-value: {p_value:.4f}, lambda: {poisson_lambda}, n: {num_samples})"
            )
        
        # Test 4: Validate using the controller's built-in validation
        validation_result = controller.validate_distribution(samples, TimingPattern.POISSON)
        assert validation_result['valid'], (
            f"Controller validation failed: {validation_result}"
        )
    
    @given(
        base_interval=st.floats(min_value=0.001, max_value=1.0),
        num_samples=st.integers(min_value=50, max_value=200)
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_5_constant_timing_low_variance(self, base_interval, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any constant timing configuration,
        the generated intervals SHALL have near-zero variance
        (coefficient of variation < 10%).
        """
        config = TimingConfig(
            pattern=TimingPattern.CONSTANT,
            base_interval=base_interval
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = [controller.get_interval() for _ in range(num_samples)]
        
        # Calculate statistics
        sample_mean = statistics.mean(samples)
        sample_std = statistics.stdev(samples) if len(samples) > 1 else 0
        
        # Coefficient of variation should be very small
        cv = (sample_std / sample_mean) if sample_mean > 0 else 0
        
        assert cv < 0.1, (
            f"Constant timing has too much variation (CV: {cv:.4f}, "
            f"mean: {sample_mean:.6f}, std: {sample_std:.6f})"
        )
        
        # All samples should be equal to base_interval
        for sample in samples:
            assert abs(sample - base_interval) < 1e-9, (
                f"Constant timing produced non-constant value: {sample} != {base_interval}"
            )
    
    @given(
        human_think_time=st.floats(min_value=0.1, max_value=2.0),
        num_samples=st.integers(min_value=50, max_value=200)
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_5_human_timing_high_variance(self, human_think_time, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any human timing configuration,
        the generated intervals SHALL have high variance
        (coefficient of variation > 30%) to mimic human unpredictability.
        """
        config = TimingConfig(
            pattern=TimingPattern.HUMAN,
            base_interval=0.001,
            human_think_time=human_think_time,
            min_interval=0.0,
            max_interval=10.0
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = [controller.get_interval() for _ in range(num_samples)]
        
        # Calculate statistics
        sample_mean = statistics.mean(samples)
        sample_std = statistics.stdev(samples) if len(samples) > 1 else 0
        
        # Coefficient of variation should be high for human-like behavior
        cv = (sample_std / sample_mean) if sample_mean > 0 else 0
        
        assert cv > 0.3, (
            f"Human timing has too little variation (CV: {cv:.4f}, "
            f"mean: {sample_mean:.6f}, std: {sample_std:.6f}). "
            f"Human behavior should be more unpredictable."
        )
        
        # Validate using controller's built-in validation
        validation_result = controller.validate_distribution(samples, TimingPattern.HUMAN)
        assert validation_result['valid'], (
            f"Controller validation failed: {validation_result}"
        )
    
    @given(
        poisson_lambda=st.floats(min_value=50.0, max_value=500.0),
        num_samples=st.integers(min_value=200, max_value=500)
    )
    @settings(max_examples=5, deadline=15000)
    def test_property_5_poisson_memoryless_property(self, poisson_lambda, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any Poisson process, the distribution SHALL be memoryless.
        That is, P(X > s + t | X > s) = P(X > t) for all s, t ≥ 0.
        
        This is a fundamental property of exponential distributions.
        """
        config = TimingConfig(
            pattern=TimingPattern.POISSON,
            poisson_lambda=poisson_lambda,
            min_interval=0.0,
            max_interval=10.0
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = [controller.get_interval() for _ in range(num_samples)]
        
        # Test memoryless property
        # Choose a threshold s
        s = 1.0 / poisson_lambda  # Use mean as threshold
        
        # Filter samples > s
        samples_greater_than_s = [x - s for x in samples if x > s]
        
        # If we have enough samples
        if len(samples_greater_than_s) >= 30:
            # The distribution of (X - s | X > s) should be the same as X
            # Both should be exponential with the same rate
            
            mean_original = statistics.mean(samples)
            mean_conditional = statistics.mean(samples_greater_than_s)
            
            # The means should be approximately equal (memoryless property)
            # Allow 30% tolerance due to sampling variation
            ratio = mean_conditional / mean_original if mean_original > 0 else 0
            
            assert 0.7 <= ratio <= 1.3, (
                f"Poisson timing violates memoryless property: "
                f"E[X] = {mean_original:.6f}, E[X-s|X>s] = {mean_conditional:.6f}, "
                f"ratio = {ratio:.3f} (should be ≈1.0)"
            )
    
    @given(
        pattern=st.sampled_from([
            TimingPattern.POISSON,
            TimingPattern.CONSTANT,
            TimingPattern.HUMAN,
            TimingPattern.RANDOM_WALK,
            TimingPattern.BROWNIAN
        ]),
        num_samples=st.integers(min_value=50, max_value=200)
    )
    @settings(max_examples=10, deadline=10000)
    def test_property_5_timing_bounds_respected(self, pattern, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any timing pattern with configured min/max bounds,
        ALL generated intervals SHALL fall within those bounds.
        """
        min_interval = 0.001
        max_interval = 1.0
        
        config = TimingConfig(
            pattern=pattern,
            base_interval=0.1,
            min_interval=min_interval,
            max_interval=max_interval,
            poisson_lambda=100.0,  # For Poisson pattern
            human_think_time=0.5   # For Human pattern
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = [controller.get_interval() for _ in range(num_samples)]
        
        # All samples must be within bounds
        for i, sample in enumerate(samples):
            assert min_interval <= sample <= max_interval, (
                f"Timing pattern {pattern.value} generated out-of-bounds interval: "
                f"{sample} not in [{min_interval}, {max_interval}] (sample {i+1}/{num_samples})"
            )
    
    @given(
        poisson_lambda=st.floats(min_value=10.0, max_value=500.0),
        num_samples=st.integers(min_value=100, max_value=300)
    )
    @settings(max_examples=5, deadline=10000)
    def test_property_5_poisson_chi_squared_goodness_of_fit(self, poisson_lambda, num_samples):
        """
        **Feature: titanium-upgrade, Property 5: Timing Distribution Accuracy**
        **Validates: Requirements 16.5, 23.2**
        
        Property: For any Poisson timing configuration,
        the generated intervals SHALL pass a chi-squared goodness-of-fit test
        for the exponential distribution.
        """
        config = TimingConfig(
            pattern=TimingPattern.POISSON,
            poisson_lambda=poisson_lambda,
            min_interval=0.0,
            max_interval=10.0
        )
        controller = TimingController(config)
        
        # Generate samples
        samples = [controller.get_interval() for _ in range(num_samples)]
        
        # Expected scale parameter (mean of exponential distribution)
        scale = 1.0 / poisson_lambda
        
        # Create bins for chi-squared test
        # Use quantiles of the exponential distribution
        num_bins = 10
        expected_freq = num_samples / num_bins
        
        # Calculate bin edges using exponential quantiles
        bin_edges = [scipy_stats.expon.ppf(i/num_bins, scale=scale) for i in range(num_bins + 1)]
        bin_edges[-1] = float('inf')  # Last bin goes to infinity
        
        # Count observed frequencies
        observed_freq = np.histogram(samples, bins=bin_edges)[0]
        
        # Chi-squared test
        # Expected frequency in each bin should be equal (uniform quantiles)
        expected = np.full(num_bins, expected_freq)
        
        chi2_stat = np.sum((observed_freq - expected) ** 2 / expected)
        
        # Degrees of freedom = num_bins - 1 - num_estimated_parameters
        # We estimated 1 parameter (lambda), so df = num_bins - 2
        df = num_bins - 2
        
        # Critical value at 0.05 significance level
        critical_value = scipy_stats.chi2.ppf(0.95, df)
        
        assert chi2_stat < critical_value, (
            f"Poisson timing failed chi-squared goodness-of-fit test: "
            f"χ² = {chi2_stat:.4f} > {critical_value:.4f} (df={df}, α=0.05, λ={poisson_lambda})"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
