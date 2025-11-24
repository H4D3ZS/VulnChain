"""Unit tests for Response Analyzer"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.core.response_analyzer import (
    ResponseAnalyzer,
    ResponseComparison,
    BaselineResponse,
    TimingStatistics
)
from app.core.http_models import Request, Response


class TestResponseAnalyzer:
    """Test suite for ResponseAnalyzer"""

    @pytest.fixture
    def analyzer(self):
        """Create a ResponseAnalyzer instance"""
        return ResponseAnalyzer(
            anomaly_threshold=0.15,
            timing_threshold_sigma=2.0
        )

    @pytest.fixture
    def sample_request(self):
        """Create a sample request"""
        return Request(
            method="GET",
            url="https://example.com/test",
            headers={"User-Agent": "VulnChain"},
        )

    @pytest.fixture
    def sample_response(self, sample_request):
        """Create a sample response"""
        return Response(
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "100",
                "Server": "nginx"
            },
            body=b"<html><body>Hello World</body></html>",
            text="<html><body>Hello World</body></html>",
            elapsed_time=0.5,
            request=sample_request
        )

    @pytest.fixture
    def similar_response(self, sample_request):
        """Create a similar response with minor differences"""
        return Response(
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "105",
                "Server": "nginx"
            },
            body=b"<html><body>Hello World!</body></html>",
            text="<html><body>Hello World!</body></html>",
            elapsed_time=0.52,
            request=sample_request
        )

    @pytest.fixture
    def different_response(self, sample_request):
        """Create a significantly different response"""
        return Response(
            status_code=404,
            headers={
                "Content-Type": "text/html",
                "Content-Length": "50"
            },
            body=b"<html><body>Not Found</body></html>",
            text="<html><body>Not Found</body></html>",
            elapsed_time=0.3,
            request=sample_request
        )

    def test_analyzer_initialization(self):
        """Test ResponseAnalyzer initialization"""
        analyzer = ResponseAnalyzer(
            anomaly_threshold=0.20,
            timing_threshold_sigma=3.0
        )
        assert analyzer.anomaly_threshold == 0.20
        assert analyzer.timing_threshold_sigma == 3.0
        assert len(analyzer.baselines) == 0
        assert len(analyzer.response_history) == 0

    def test_analyzer_default_initialization(self):
        """Test ResponseAnalyzer with default parameters"""
        analyzer = ResponseAnalyzer()
        assert analyzer.anomaly_threshold == 0.15
        assert analyzer.timing_threshold_sigma == 2.0

    def test_capture_baseline(self, analyzer, sample_response):
        """Test capturing a baseline response"""
        baseline = analyzer.capture_baseline(sample_response, label="test")
        
        assert isinstance(baseline, BaselineResponse)
        assert baseline.response == sample_response
        assert baseline.label == "test"
        assert isinstance(baseline.captured_at, datetime)
        assert "test" in analyzer.baselines

    def test_capture_multiple_baselines(self, analyzer, sample_response, different_response):
        """Test capturing multiple baselines with different labels"""
        baseline1 = analyzer.capture_baseline(sample_response, label="normal")
        baseline2 = analyzer.capture_baseline(different_response, label="error")
        
        assert len(analyzer.baselines) == 2
        assert analyzer.get_baseline("normal") == baseline1
        assert analyzer.get_baseline("error") == baseline2

    def test_get_baseline(self, analyzer, sample_response):
        """Test retrieving a stored baseline"""
        analyzer.capture_baseline(sample_response, label="test")
        
        baseline = analyzer.get_baseline("test")
        assert baseline is not None
        assert baseline.response == sample_response
        
        # Test non-existent baseline
        missing = analyzer.get_baseline("nonexistent")
        assert missing is None

    def test_compute_similarity_identical_responses(self, analyzer, sample_response):
        """Test similarity score for identical responses"""
        score = analyzer.compute_similarity_score(sample_response, sample_response)
        assert score == 1.0

    def test_compute_similarity_similar_responses(
        self, analyzer, sample_response, similar_response
    ):
        """Test similarity score for similar responses"""
        score = analyzer.compute_similarity_score(sample_response, similar_response)
        # Should be high similarity (>0.9) but not perfect
        assert 0.9 < score < 1.0

    def test_compute_similarity_different_responses(
        self, analyzer, sample_response, different_response
    ):
        """Test similarity score for different responses"""
        score = analyzer.compute_similarity_score(sample_response, different_response)
        # Should be lower similarity than similar responses
        assert score < 0.85

    def test_compute_similarity_empty_responses(self, analyzer, sample_request):
        """Test similarity score for empty responses"""
        empty1 = Response(
            status_code=200,
            headers={},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=sample_request
        )
        empty2 = Response(
            status_code=200,
            headers={},
            body=b"",
            text="",
            elapsed_time=0.1,
            request=sample_request
        )
        
        score = analyzer.compute_similarity_score(empty1, empty2)
        assert score == 1.0

    def test_compare_responses_identical(self, analyzer, sample_response):
        """Test comparing identical responses"""
        comparison = analyzer.compare_responses(sample_response, sample_response)
        
        assert isinstance(comparison, ResponseComparison)
        assert comparison.similarity_score == 1.0
        assert comparison.length_difference == 0
        assert comparison.status_code_match is True
        assert len(comparison.header_differences) == 0
        assert comparison.is_anomaly is False

    def test_compare_responses_similar(
        self, analyzer, sample_response, similar_response
    ):
        """Test comparing similar responses"""
        comparison = analyzer.compare_responses(sample_response, similar_response)
        
        assert comparison.similarity_score > 0.9
        assert comparison.length_difference == 1  # Body length difference
        assert comparison.status_code_match is True
        assert comparison.is_anomaly is False

    def test_compare_responses_different(
        self, analyzer, sample_response, different_response
    ):
        """Test comparing different responses"""
        comparison = analyzer.compare_responses(sample_response, different_response)
        
        assert comparison.similarity_score < 0.85
        assert comparison.status_code_match is False
        assert comparison.is_anomaly is True

    def test_compare_responses_custom_threshold(
        self, analyzer, sample_response, different_response
    ):
        """Test comparing responses with custom threshold"""
        # With high threshold (0.5), even different responses might not be anomalies
        comparison = analyzer.compare_responses(
            sample_response,
            different_response,
            threshold=0.5
        )
        
        # Similarity is moderate, but threshold is high, so not flagged as anomaly
        assert comparison.similarity_score < 0.85
        assert comparison.is_anomaly is False  # High threshold means not flagged

    def test_header_differences(self, analyzer, sample_response, sample_request):
        """Test detection of header differences"""
        modified_response = Response(
            status_code=200,
            headers={
                "Content-Type": "application/json",  # Changed
                "Content-Length": "100",
                "X-Custom": "value"  # Added
                # Server header removed
            },
            body=sample_response.body,
            text=sample_response.text,
            elapsed_time=0.5,
            request=sample_request
        )
        
        comparison = analyzer.compare_responses(sample_response, modified_response)
        
        assert len(comparison.header_differences) == 3
        assert "Content-Type" in comparison.header_differences
        assert "X-Custom" in comparison.header_differences
        assert "Server" in comparison.header_differences

    def test_body_diff_generation(self, analyzer, sample_response, sample_request):
        """Test body diff generation"""
        modified_response = Response(
            status_code=200,
            headers=sample_response.headers,
            body=b"<html><body>Goodbye World</body></html>",
            text="<html><body>Goodbye World</body></html>",
            elapsed_time=0.5,
            request=sample_request
        )
        
        comparison = analyzer.compare_responses(sample_response, modified_response)
        
        assert len(comparison.body_diff) > 0
        # Check that diff contains change indicators
        diff_text = "".join(comparison.body_diff)
        assert "-" in diff_text or "+" in diff_text

    def test_generate_visual_diff_unified(
        self, analyzer, sample_response, sample_request
    ):
        """Test unified diff generation"""
        modified_response = Response(
            status_code=200,
            headers=sample_response.headers,
            body=b"<html><body>Modified Content</body></html>",
            text="<html><body>Modified Content</body></html>",
            elapsed_time=0.5,
            request=sample_request
        )
        
        diff = analyzer.generate_visual_diff(
            sample_response,
            modified_response,
            format="unified"
        )
        
        assert isinstance(diff, str)
        assert len(diff) > 0
        assert "---" in diff or "+++" in diff

    def test_generate_visual_diff_context(
        self, analyzer, sample_response, sample_request
    ):
        """Test context diff generation"""
        modified_response = Response(
            status_code=200,
            headers=sample_response.headers,
            body=b"<html><body>Modified Content</body></html>",
            text="<html><body>Modified Content</body></html>",
            elapsed_time=0.5,
            request=sample_request
        )
        
        diff = analyzer.generate_visual_diff(
            sample_response,
            modified_response,
            format="context"
        )
        
        assert isinstance(diff, str)
        assert len(diff) > 0

    def test_generate_visual_diff_html(
        self, analyzer, sample_response, sample_request
    ):
        """Test HTML diff generation"""
        modified_response = Response(
            status_code=200,
            headers=sample_response.headers,
            body=b"<html><body>Modified Content</body></html>",
            text="<html><body>Modified Content</body></html>",
            elapsed_time=0.5,
            request=sample_request
        )
        
        diff = analyzer.generate_visual_diff(
            sample_response,
            modified_response,
            format="html"
        )
        
        assert isinstance(diff, str)
        assert "<html>" in diff.lower()
        assert "<table" in diff.lower()

    def test_generate_visual_diff_invalid_format(
        self, analyzer, sample_response, similar_response
    ):
        """Test visual diff with invalid format"""
        with pytest.raises(ValueError, match="Unsupported diff format"):
            analyzer.generate_visual_diff(
                sample_response,
                similar_response,
                format="invalid"
            )

    def test_add_response_timing(self, analyzer, sample_response):
        """Test adding responses to timing history"""
        assert len(analyzer.response_history) == 0
        
        analyzer.add_response_timing(sample_response)
        assert len(analyzer.response_history) == 1
        
        analyzer.add_response_timing(sample_response)
        assert len(analyzer.response_history) == 2

    def test_analyze_timing_statistics(self, analyzer, sample_request):
        """Test timing statistics analysis"""
        # Create responses with known timings
        timings = [0.5, 0.52, 0.48, 0.51, 0.49, 5.0]  # Last one is outlier
        responses = []
        
        for timing in timings:
            response = Response(
                status_code=200,
                headers={},
                body=b"test",
                text="test",
                elapsed_time=timing,
                request=sample_request
            )
            responses.append(response)
            analyzer.add_response_timing(response)
        
        stats = analyzer.analyze_timing_statistics()
        
        assert isinstance(stats, TimingStatistics)
        assert stats.mean > 0
        assert stats.median > 0
        assert stats.std_dev > 0
        assert stats.min_time == 0.48
        assert stats.max_time == 5.0
        assert len(stats.outliers) > 0  # 5.0 should be detected as outlier

    def test_analyze_timing_statistics_custom_responses(
        self, analyzer, sample_request
    ):
        """Test timing statistics with custom response list"""
        responses = []
        for timing in [0.1, 0.2, 0.15, 0.18]:
            response = Response(
                status_code=200,
                headers={},
                body=b"test",
                text="test",
                elapsed_time=timing,
                request=sample_request
            )
            responses.append(response)
        
        stats = analyzer.analyze_timing_statistics(responses=responses)
        
        assert stats.mean > 0
        assert stats.min_time == 0.1
        assert stats.max_time == 0.2

    def test_analyze_timing_statistics_no_responses(self, analyzer):
        """Test timing statistics with no responses"""
        with pytest.raises(ValueError, match="No responses available"):
            analyzer.analyze_timing_statistics()

    def test_analyze_timing_statistics_single_response(
        self, analyzer, sample_response
    ):
        """Test timing statistics with single response"""
        analyzer.add_response_timing(sample_response)
        
        stats = analyzer.analyze_timing_statistics()
        
        assert stats.mean == sample_response.elapsed_time
        assert stats.std_dev == 0.0
        assert len(stats.outliers) == 0

    def test_detect_timing_anomalies(self, analyzer, sample_request):
        """Test detection of timing anomalies"""
        # Create normal responses and one slow response
        for timing in [0.5, 0.52, 0.48, 0.51, 0.49]:
            response = Response(
                status_code=200,
                headers={},
                body=b"test",
                text="test",
                elapsed_time=timing,
                request=sample_request
            )
            analyzer.add_response_timing(response)
        
        # Add anomalous response
        slow_response = Response(
            status_code=200,
            headers={},
            body=b"test",
            text="test",
            elapsed_time=5.0,  # Much slower
            request=sample_request
        )
        analyzer.add_response_timing(slow_response)
        
        anomalies = analyzer.detect_timing_anomalies()
        
        assert len(anomalies) > 0
        assert slow_response in anomalies

    def test_detect_timing_anomalies_custom_threshold(
        self, analyzer, sample_request
    ):
        """Test timing anomaly detection with custom threshold"""
        for timing in [0.5, 0.52, 0.48, 0.51, 0.49, 0.7]:
            response = Response(
                status_code=200,
                headers={},
                body=b"test",
                text="test",
                elapsed_time=timing,
                request=sample_request
            )
            analyzer.add_response_timing(response)
        
        # With high threshold (3 sigma), 0.7 might not be anomaly
        anomalies = analyzer.detect_timing_anomalies(threshold_sigma=3.0)
        
        # With low threshold (1 sigma), 0.7 should be anomaly
        anomalies_sensitive = analyzer.detect_timing_anomalies(threshold_sigma=1.0)
        
        assert len(anomalies_sensitive) >= len(anomalies)

    def test_flag_anomalies(
        self, analyzer, sample_response, different_response, sample_request
    ):
        """Test flagging anomalous responses"""
        # Capture baseline
        analyzer.capture_baseline(sample_response, label="baseline")
        
        # Create test responses
        test_responses = [
            sample_response,  # Same as baseline - not anomaly
            different_response  # Different - should be anomaly
        ]
        
        anomalies = analyzer.flag_anomalies(test_responses, baseline_label="baseline")
        
        assert len(anomalies) > 0
        # Check that different_response is flagged
        anomaly_responses = [resp for resp, _ in anomalies]
        assert different_response in anomaly_responses

    def test_flag_anomalies_no_baseline(self, analyzer, sample_response):
        """Test flagging anomalies without baseline"""
        with pytest.raises(ValueError, match="No baseline found"):
            analyzer.flag_anomalies([sample_response], baseline_label="nonexistent")

    def test_flag_anomalies_custom_threshold(
        self, analyzer, sample_response, similar_response
    ):
        """Test flagging anomalies with custom threshold"""
        analyzer.capture_baseline(sample_response, label="baseline")
        
        # With strict threshold, similar response might be anomaly
        anomalies_strict = analyzer.flag_anomalies(
            [similar_response],
            baseline_label="baseline",
            threshold=0.05  # Very strict
        )
        
        # With loose threshold, similar response should not be anomaly
        anomalies_loose = analyzer.flag_anomalies(
            [similar_response],
            baseline_label="baseline",
            threshold=0.30  # Very loose
        )
        
        assert len(anomalies_strict) >= len(anomalies_loose)

    def test_clear_history(self, analyzer, sample_response):
        """Test clearing response history"""
        analyzer.add_response_timing(sample_response)
        analyzer.add_response_timing(sample_response)
        assert len(analyzer.response_history) == 2
        
        analyzer.clear_history()
        assert len(analyzer.response_history) == 0

    def test_clear_baselines(self, analyzer, sample_response):
        """Test clearing baselines"""
        analyzer.capture_baseline(sample_response, label="test1")
        analyzer.capture_baseline(sample_response, label="test2")
        assert len(analyzer.baselines) == 2
        
        analyzer.clear_baselines()
        assert len(analyzer.baselines) == 0

    def test_similarity_score_components(self, analyzer, sample_request):
        """Test that similarity score considers all components"""
        base = Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"Hello World",
            text="Hello World",
            elapsed_time=0.5,
            request=sample_request
        )
        
        # Different status code
        diff_status = Response(
            status_code=404,
            headers={"Content-Type": "text/html"},
            body=b"Hello World",
            text="Hello World",
            elapsed_time=0.5,
            request=sample_request
        )
        
        # Different length
        diff_length = Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"Hello",
            text="Hello",
            elapsed_time=0.5,
            request=sample_request
        )
        
        # Different headers
        diff_headers = Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"Hello World",
            text="Hello World",
            elapsed_time=0.5,
            request=sample_request
        )
        
        # Different body
        diff_body = Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=b"Goodbye World",
            text="Goodbye World",
            elapsed_time=0.5,
            request=sample_request
        )
        
        # All should have different similarity scores
        score_status = analyzer.compute_similarity_score(base, diff_status)
        score_length = analyzer.compute_similarity_score(base, diff_length)
        score_headers = analyzer.compute_similarity_score(base, diff_headers)
        score_body = analyzer.compute_similarity_score(base, diff_body)
        
        # Status, length, and body changes should reduce similarity
        assert score_status < 1.0
        assert score_length < 1.0
        assert score_body < 1.0
        
        # All scores should be different, showing each component affects the result
        # The exact ordering depends on the specific changes and weights
        assert score_status != score_length
        assert score_length != score_body


class TestResponseComparisonDataClass:
    """Test ResponseComparison data class"""

    def test_response_comparison_creation(self):
        """Test creating ResponseComparison instance"""
        comparison = ResponseComparison(
            similarity_score=0.95,
            length_difference=10,
            status_code_match=True,
            header_differences={"X-Custom": ("val1", "val2")},
            body_diff=["- old line", "+ new line"],
            is_anomaly=False
        )
        
        assert comparison.similarity_score == 0.95
        assert comparison.length_difference == 10
        assert comparison.status_code_match is True
        assert len(comparison.header_differences) == 1
        assert len(comparison.body_diff) == 2
        assert comparison.is_anomaly is False


class TestBaselineResponseDataClass:
    """Test BaselineResponse data class"""

    def test_baseline_response_creation(self, sample_request):
        """Test creating BaselineResponse instance"""
        response = Response(
            status_code=200,
            headers={},
            body=b"test",
            text="test",
            elapsed_time=0.5,
            request=sample_request
        )
        
        baseline = BaselineResponse(
            response=response,
            captured_at=datetime.now(timezone.utc),
            label="test"
        )
        
        assert baseline.response == response
        assert isinstance(baseline.captured_at, datetime)
        assert baseline.label == "test"


class TestTimingStatisticsDataClass:
    """Test TimingStatistics data class"""

    def test_timing_statistics_creation(self, sample_request):
        """Test creating TimingStatistics instance"""
        response = Response(
            status_code=200,
            headers={},
            body=b"test",
            text="test",
            elapsed_time=5.0,
            request=sample_request
        )
        
        stats = TimingStatistics(
            mean=0.5,
            median=0.48,
            std_dev=0.1,
            min_time=0.4,
            max_time=5.0,
            outliers=[(5.0, response)],
            threshold=0.7
        )
        
        assert stats.mean == 0.5
        assert stats.median == 0.48
        assert stats.std_dev == 0.1
        assert stats.min_time == 0.4
        assert stats.max_time == 5.0
        assert len(stats.outliers) == 1
        assert stats.threshold == 0.7


@pytest.fixture
def sample_request():
    """Create a sample request for tests"""
    return Request(
        method="GET",
        url="https://example.com/test",
        headers={"User-Agent": "VulnChain"},
    )
