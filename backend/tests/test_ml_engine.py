"""Tests for ML Engine"""

import pytest
from datetime import datetime

from app.core.ml_engine import (
    MLEngine,
    TargetInfo,
    VulnerabilityPrediction,
    ErrorAnalysis,
    AttackVector,
    RankedVector,
    AttackAttempt,
    AttackResult
)


class TestVulnerabilityPrediction:
    """Test vulnerability prediction functionality"""
    
    def test_predict_sql_injection_for_mysql(self):
        """Test SQL injection prediction for MySQL target"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://example.com",
            technologies=["MySQL", "PHP"],
            detected_language="php"
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should predict SQL injection
        sql_predictions = [p for p in predictions if p.vulnerability_type == "sql_injection"]
        assert len(sql_predictions) > 0
        assert sql_predictions[0].confidence > 0.2
    
    def test_predict_nosql_injection_for_mongodb(self):
        """Test NoSQL injection prediction for MongoDB target"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://api.example.com",
            technologies=["MongoDB", "Node.js"],
            detected_language="nodejs"
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should predict NoSQL injection
        nosql_predictions = [p for p in predictions if p.vulnerability_type == "nosql_injection"]
        assert len(nosql_predictions) > 0
        assert nosql_predictions[0].confidence > 0.2
    
    def test_predict_ssti_for_jinja2(self):
        """Test SSTI prediction for Jinja2 target"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://app.example.com",
            technologies=["Python", "Flask", "Jinja2"],
            frameworks=["Flask"],
            detected_language="python"
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should predict SSTI
        ssti_predictions = [p for p in predictions if p.vulnerability_type == "ssti"]
        assert len(ssti_predictions) > 0
        assert ssti_predictions[0].confidence > 0.3
    
    def test_predict_jwt_manipulation_with_bearer_token(self):
        """Test JWT manipulation prediction when bearer token detected"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://api.example.com",
            response_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should predict JWT manipulation
        jwt_predictions = [p for p in predictions if p.vulnerability_type == "jwt_manipulation"]
        assert len(jwt_predictions) > 0
        assert jwt_predictions[0].confidence > 0.2
    
    def test_predict_graphql_for_api_with_graphql(self):
        """Test GraphQL prediction for API with GraphQL"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://api.example.com/graphql",
            technologies=["GraphQL", "Apollo"],
            has_api=True
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should predict GraphQL vulnerabilities
        graphql_predictions = [p for p in predictions if p.vulnerability_type == "graphql"]
        assert len(graphql_predictions) > 0
        assert graphql_predictions[0].confidence > 0.4
    
    def test_predictions_sorted_by_confidence(self):
        """Test that predictions are sorted by confidence"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://example.com",
            technologies=["PHP", "MySQL", "Jinja2", "MongoDB"],
            detected_language="php"
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Check that predictions are sorted by confidence (descending)
        for i in range(len(predictions) - 1):
            assert predictions[i].confidence >= predictions[i + 1].confidence or \
                   predictions[i].priority <= predictions[i + 1].priority
    
    def test_no_predictions_for_unknown_tech(self):
        """Test that minimal predictions for unknown technologies"""
        ml_engine = MLEngine()
        
        target = TargetInfo(
            url="https://example.com",
            technologies=["UnknownTech"],
            detected_language="unknown"
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        
        # Should have few or no predictions
        assert len(predictions) <= 3


class TestErrorAnalysis:
    """Test error message analysis functionality"""
    
    def test_analyze_sql_error(self):
        """Test analysis of SQL error message"""
        ml_engine = MLEngine()
        
        error = "You have an error in your SQL syntax near '' at line 1"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "sql_error"
        assert analysis.confidence > 0.5
        assert len(analysis.hints) > 0
        assert "SQL injection" in analysis.suggested_exploits[0]
    
    def test_analyze_php_error_with_file_path(self):
        """Test analysis of PHP error with file path extraction"""
        ml_engine = MLEngine()
        
        error = "Warning: mysql_fetch_array() in /var/www/html/login.php on line 42"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "php_error"
        assert "file_path" in analysis.extracted_info
        assert "/var/www/html/login.php" in analysis.extracted_info["file_path"]
        assert "line_number" in analysis.extracted_info
        assert analysis.extracted_info["line_number"] == "42"
    
    def test_analyze_python_traceback(self):
        """Test analysis of Python traceback"""
        ml_engine = MLEngine()
        
        error = """
        Traceback (most recent call last):
          File "/app/views.py", line 23, in render_template
        jinja2.exceptions.UndefinedError: 'user' is undefined
        """
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "template_error"
        assert "SSTI" in " ".join(analysis.suggested_exploits)
    
    def test_analyze_command_injection_error(self):
        """Test analysis of command injection error"""
        ml_engine = MLEngine()
        
        error = "sh: 1: curl: command not found"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "command_error"
        assert analysis.confidence > 0.5
        assert "Command injection" in analysis.hints[0]
    
    def test_analyze_java_exception(self):
        """Test analysis of Java exception"""
        ml_engine = MLEngine()
        
        error = "java.io.IOException: Connection refused at com.example.Service.connect"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "java_error"
        assert len(analysis.suggested_exploits) > 0
    
    def test_analyze_xml_error(self):
        """Test analysis of XML error"""
        ml_engine = MLEngine()
        
        error = "XML parsing error: External entity not defined"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "xml_error"
        assert "XXE" in " ".join(analysis.suggested_exploits)
    
    def test_analyze_nosql_error(self):
        """Test analysis of NoSQL error"""
        ml_engine = MLEngine()
        
        error = "MongoError: Invalid operator $where in query"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "nosql_error"
        assert "NoSQL" in " ".join(analysis.suggested_exploits)
    
    def test_analyze_generic_error(self):
        """Test analysis of generic error"""
        ml_engine = MLEngine()
        
        error = "Something went wrong"
        analysis = ml_engine.analyze_error_message(error)
        
        assert analysis.error_type == "generic"
        assert analysis.confidence < 0.5


class TestAttackVectorRanking:
    """Test attack vector ranking functionality"""
    
    def test_rank_vectors_by_complexity(self):
        """Test that low complexity vectors rank higher"""
        ml_engine = MLEngine()
        
        vectors = [
            AttackVector(
                module_name="high_complexity",
                vulnerability_type="test",
                description="High complexity",
                estimated_time=60.0,
                complexity="high"
            ),
            AttackVector(
                module_name="low_complexity",
                vulnerability_type="test",
                description="Low complexity",
                estimated_time=60.0,
                complexity="low"
            )
        ]
        
        ranked = ml_engine.rank_attack_vectors(vectors, {})
        
        # Low complexity should rank higher
        assert ranked[0].vector.complexity == "low"
        assert ranked[0].exploitation_probability > ranked[1].exploitation_probability
    
    def test_rank_vectors_by_time(self):
        """Test that faster vectors rank higher"""
        ml_engine = MLEngine()
        
        vectors = [
            AttackVector(
                module_name="slow",
                vulnerability_type="test",
                description="Slow",
                estimated_time=300.0,
                complexity="medium"
            ),
            AttackVector(
                module_name="fast",
                vulnerability_type="test",
                description="Fast",
                estimated_time=30.0,
                complexity="medium"
            )
        ]
        
        ranked = ml_engine.rank_attack_vectors(vectors, {})
        
        # Faster should rank higher
        assert ranked[0].vector.module_name == "fast"
        assert ranked[0].time_to_flag < ranked[1].time_to_flag
    
    def test_rank_vectors_with_technology_context(self):
        """Test ranking with technology context"""
        ml_engine = MLEngine()
        
        vectors = [
            AttackVector(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                description="SQL injection",
                estimated_time=60.0,
                complexity="medium"
            ),
            AttackVector(
                module_name="nosql_injection",
                vulnerability_type="nosql_injection",
                description="NoSQL injection",
                estimated_time=60.0,
                complexity="medium"
            )
        ]
        
        # Context with MySQL should boost SQL injection
        context = {"technologies": ["MySQL", "PHP"]}
        ranked = ml_engine.rank_attack_vectors(vectors, context)
        
        # SQL injection should rank higher with MySQL context
        assert ranked[0].vector.vulnerability_type == "sql_injection"
    
    def test_ranked_vectors_have_ranks(self):
        """Test that ranked vectors have sequential ranks"""
        ml_engine = MLEngine()
        
        vectors = [
            AttackVector(
                module_name=f"test_{i}",
                vulnerability_type="test",
                description=f"Test {i}",
                estimated_time=60.0,
                complexity="medium"
            )
            for i in range(5)
        ]
        
        ranked = ml_engine.rank_attack_vectors(vectors, {})
        
        # Check ranks are sequential
        for i, r in enumerate(ranked, 1):
            assert r.rank == i
    
    def test_score_calculation(self):
        """Test that score is calculated correctly"""
        ml_engine = MLEngine()
        
        vector = AttackVector(
            module_name="test",
            vulnerability_type="test",
            description="Test",
            estimated_time=60.0,
            complexity="low"
        )
        
        ranked = ml_engine.rank_attack_vectors([vector], {})
        
        # Score should be positive
        assert ranked[0].score > 0
        # Score should be exploitation_prob / (time_to_flag / 60)
        expected_score = ranked[0].exploitation_probability / (ranked[0].time_to_flag / 60.0)
        assert abs(ranked[0].score - expected_score) < 0.01


class TestAdaptiveLearning:
    """Test adaptive learning functionality"""
    
    def test_learn_from_successful_attempt(self):
        """Test learning from successful attack attempt"""
        ml_engine = MLEngine()
        
        attempt = AttackAttempt(
            module_name="sql_injection",
            vulnerability_type="sql_injection",
            target_url="https://example.com",
            payload="' OR '1'='1",
            timestamp=datetime.now()
        )
        
        result = AttackResult(
            success=True,
            vulnerability_found=True,
            response_time=0.5,
            status_code=200,
            flags_found=["CTF{success}"]
        )
        
        ml_engine.learn_from_attempt(attempt, result)
        
        # Should have recorded success
        assert len(ml_engine.success_patterns["sql_injection"]) > 0
    
    def test_learn_from_failed_attempt(self):
        """Test learning from failed attack attempt"""
        ml_engine = MLEngine()
        
        attempt = AttackAttempt(
            module_name="xss",
            vulnerability_type="xss",
            target_url="https://example.com",
            payload="<script>alert(1)</script>",
            timestamp=datetime.now()
        )
        
        result = AttackResult(
            success=False,
            vulnerability_found=False,
            response_time=0.3,
            status_code=403
        )
        
        ml_engine.learn_from_attempt(attempt, result)
        
        # Should have recorded failure
        assert len(ml_engine.failure_patterns["xss"]) > 0
    
    def test_adaptive_strategy_with_no_history(self):
        """Test adaptive strategy with no historical data"""
        ml_engine = MLEngine()
        
        strategy = ml_engine.get_adaptive_strategy(
            "https://example.com",
            "sql_injection"
        )
        
        assert strategy["strategy"] == "default"
        assert "No historical data" in strategy["recommendations"][0]
    
    def test_adaptive_strategy_with_high_success_rate(self):
        """Test adaptive strategy with high success rate"""
        ml_engine = MLEngine()
        
        target_url = "https://example.com"
        
        # Record multiple successful attempts
        for i in range(5):
            attempt = AttackAttempt(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                target_url=target_url,
                payload=f"payload_{i}",
                timestamp=datetime.now()
            )
            result = AttackResult(
                success=True,
                vulnerability_found=True,
                response_time=0.5,
                status_code=200
            )
            ml_engine.learn_from_attempt(attempt, result)
        
        strategy = ml_engine.get_adaptive_strategy(target_url, "sql_injection")
        
        assert strategy["strategy"] == "aggressive"
        assert strategy["success_rate"] > 0.5
    
    def test_adaptive_strategy_detects_waf(self):
        """Test that adaptive strategy detects WAF"""
        ml_engine = MLEngine()
        
        target_url = "https://example.com"
        
        # Record multiple failed attempts with WAF blocking
        for i in range(5):
            attempt = AttackAttempt(
                module_name="xss",
                vulnerability_type="xss",
                target_url=target_url,
                payload=f"<script>alert({i})</script>",
                timestamp=datetime.now()
            )
            result = AttackResult(
                success=False,
                vulnerability_found=False,
                response_time=0.3,
                status_code=403,
                error_message="Blocked by WAF"
            )
            ml_engine.learn_from_attempt(attempt, result)
        
        strategy = ml_engine.get_adaptive_strategy(target_url, "xss")
        
        assert "enable_waf_bypass" in strategy["adjustments"]
        assert strategy["adjustments"]["enable_waf_bypass"] is True
    
    def test_adaptive_strategy_detects_rate_limiting(self):
        """Test that adaptive strategy detects rate limiting"""
        ml_engine = MLEngine()
        
        target_url = "https://example.com"
        
        # Record multiple failed attempts with timeouts
        for i in range(5):
            attempt = AttackAttempt(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                target_url=target_url,
                payload=f"payload_{i}",
                timestamp=datetime.now()
            )
            result = AttackResult(
                success=False,
                vulnerability_found=False,
                response_time=30.0,
                status_code=429,
                error_message="Request timeout"
            )
            ml_engine.learn_from_attempt(attempt, result)
        
        strategy = ml_engine.get_adaptive_strategy(target_url, "sql_injection")
        
        assert "reduce_rate" in strategy["adjustments"]
        assert strategy["adjustments"]["reduce_rate"] is True
    
    def test_attack_history_limited(self):
        """Test that attack history is limited to prevent memory issues"""
        ml_engine = MLEngine()
        
        # Record many attempts
        for i in range(1500):
            attempt = AttackAttempt(
                module_name="test",
                vulnerability_type="test",
                target_url="https://example.com",
                payload=f"payload_{i}",
                timestamp=datetime.now()
            )
            result = AttackResult(
                success=True,
                vulnerability_found=True,
                response_time=0.5,
                status_code=200
            )
            ml_engine.learn_from_attempt(attempt, result)
        
        # History should be limited
        assert len(ml_engine.attack_history) <= 1000


class TestLearningDataPersistence:
    """Test learning data export and import"""
    
    def test_export_learning_data(self):
        """Test exporting learning data"""
        ml_engine = MLEngine()
        
        # Add some learning data
        attempt = AttackAttempt(
            module_name="sql_injection",
            vulnerability_type="sql_injection",
            target_url="https://example.com",
            payload="test",
            timestamp=datetime.now()
        )
        result = AttackResult(
            success=True,
            vulnerability_found=True,
            response_time=0.5,
            status_code=200
        )
        ml_engine.learn_from_attempt(attempt, result)
        
        # Export data
        data = ml_engine.export_learning_data()
        
        assert "success_patterns" in data
        assert "failure_patterns" in data
        assert "attack_history_count" in data
        assert data["attack_history_count"] == 1
    
    def test_import_learning_data(self):
        """Test importing learning data"""
        ml_engine = MLEngine()
        
        # Create learning data
        data = {
            "success_patterns": {
                "sql_injection": ["pattern1", "pattern2"]
            },
            "failure_patterns": {
                "xss": ["pattern3"]
            }
        }
        
        # Import data
        ml_engine.import_learning_data(data)
        
        assert len(ml_engine.success_patterns["sql_injection"]) == 2
        assert len(ml_engine.failure_patterns["xss"]) == 1
    
    def test_export_import_round_trip(self):
        """Test that export and import preserve data"""
        ml_engine1 = MLEngine()
        
        # Add learning data
        for i in range(5):
            attempt = AttackAttempt(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                target_url="https://example.com",
                payload=f"payload_{i}",
                timestamp=datetime.now()
            )
            result = AttackResult(
                success=True,
                vulnerability_found=True,
                response_time=0.5,
                status_code=200
            )
            ml_engine1.learn_from_attempt(attempt, result)
        
        # Export
        data = ml_engine1.export_learning_data()
        
        # Import into new engine
        ml_engine2 = MLEngine()
        ml_engine2.import_learning_data(data)
        
        # Should have same patterns
        assert len(ml_engine2.success_patterns["sql_injection"]) == len(ml_engine1.success_patterns["sql_injection"])


class TestIntegration:
    """Integration tests for ML Engine"""
    
    def test_complete_workflow(self):
        """Test complete ML engine workflow"""
        ml_engine = MLEngine()
        
        # Step 1: Predict vulnerabilities
        target = TargetInfo(
            url="https://example.com",
            technologies=["PHP", "MySQL"],
            detected_language="php",
            error_messages=["SQL syntax error"]
        )
        
        predictions = ml_engine.predict_vulnerabilities(target)
        assert len(predictions) > 0
        
        # Step 2: Analyze error
        analysis = ml_engine.analyze_error_message("SQL syntax error near ''")
        assert analysis.error_type == "sql_error"
        
        # Step 3: Rank vectors
        vectors = [
            AttackVector(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                description="SQL injection",
                estimated_time=60.0,
                complexity="medium"
            )
        ]
        
        ranked = ml_engine.rank_attack_vectors(vectors, {"technologies": ["MySQL"]})
        assert len(ranked) == 1
        
        # Step 4: Learn from attempt
        attempt = AttackAttempt(
            module_name="sql_injection",
            vulnerability_type="sql_injection",
            target_url="https://example.com",
            payload="' OR '1'='1",
            timestamp=datetime.now()
        )
        
        result = AttackResult(
            success=True,
            vulnerability_found=True,
            response_time=0.5,
            status_code=200
        )
        
        ml_engine.learn_from_attempt(attempt, result)
        
        # Step 5: Get adaptive strategy
        strategy = ml_engine.get_adaptive_strategy("https://example.com", "sql_injection")
        assert strategy["success_rate"] > 0
