"""
ML Engine Demo

This script demonstrates the capabilities of the ML Engine for vulnerability
prediction, error analysis, attack vector ranking, and adaptive learning.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.ml_engine import (
    MLEngine, TargetInfo, VulnerabilityPrediction,
    ErrorAnalysis, AttackVector, RankedVector,
    AttackAttempt, AttackResult
)
from datetime import datetime
import json


def demo_vulnerability_prediction():
    """Demonstrate vulnerability prediction"""
    print("=" * 80)
    print("VULNERABILITY PREDICTION DEMO")
    print("=" * 80)
    
    ml_engine = MLEngine()
    
    # Example 1: PHP/MySQL application
    print("\n1. PHP/MySQL Application")
    print("-" * 40)
    target1 = TargetInfo(
        url="https://example.com",
        technologies=["PHP", "MySQL", "Apache"],
        frameworks=["WordPress"],
        server_software="Apache/2.4.41",
        response_headers={"X-Powered-By": "PHP/7.4.3"},
        error_messages=["Warning: mysql_fetch_array() expects parameter 1"],
        detected_cms="wordpress",
        detected_language="php"
    )
    
    predictions1 = ml_engine.predict_vulnerabilities(target1)
    for pred in predictions1[:5]:  # Top 5
        print(f"\n{pred.vulnerability_type.upper()}")
        print(f"  Confidence: {pred.confidence:.2%}")
        print(f"  Priority: {pred.priority}")
        print(f"  Reasoning: {pred.reasoning}")
        print(f"  Suggested Modules: {', '.join(pred.suggested_modules)}")
    
    # Example 2: Node.js/MongoDB application
    print("\n\n2. Node.js/MongoDB Application")
    print("-" * 40)
    target2 = TargetInfo(
        url="https://api.example.com",
        technologies=["Node.js", "MongoDB", "Express"],
        frameworks=["Express"],
        server_software="nginx/1.18.0",
        response_headers={"X-Powered-By": "Express"},
        detected_language="nodejs",
        has_api=True,
        has_javascript=True
    )
    
    predictions2 = ml_engine.predict_vulnerabilities(target2)
    for pred in predictions2[:5]:  # Top 5
        print(f"\n{pred.vulnerability_type.upper()}")
        print(f"  Confidence: {pred.confidence:.2%}")
        print(f"  Priority: {pred.priority}")
        print(f"  Reasoning: {pred.reasoning}")
    
    # Example 3: Python/Flask application
    print("\n\n3. Python/Flask Application")
    print("-" * 40)
    target3 = TargetInfo(
        url="https://app.example.com",
        technologies=["Python", "Flask", "Jinja2"],
        frameworks=["Flask"],
        server_software="gunicorn/20.1.0",
        error_messages=["jinja2.exceptions.TemplateSyntaxError"],
        detected_language="python"
    )
    
    predictions3 = ml_engine.predict_vulnerabilities(target3)
    for pred in predictions3[:5]:  # Top 5
        print(f"\n{pred.vulnerability_type.upper()}")
        print(f"  Confidence: {pred.confidence:.2%}")
        print(f"  Priority: {pred.priority}")
        print(f"  Reasoning: {pred.reasoning}")


def demo_error_analysis():
    """Demonstrate error message analysis"""
    print("\n\n" + "=" * 80)
    print("ERROR MESSAGE ANALYSIS DEMO")
    print("=" * 80)
    
    ml_engine = MLEngine()
    
    # Example 1: SQL Error
    print("\n1. SQL Error")
    print("-" * 40)
    sql_error = """
    You have an error in your SQL syntax; check the manual that corresponds to your 
    MySQL server version for the right syntax to use near '' at line 1
    """
    analysis1 = ml_engine.analyze_error_message(sql_error)
    print(f"Error Type: {analysis1.error_type}")
    print(f"Confidence: {analysis1.confidence:.2%}")
    print(f"Hints:")
    for hint in analysis1.hints:
        print(f"  - {hint}")
    print(f"Suggested Exploits:")
    for exploit in analysis1.suggested_exploits:
        print(f"  - {exploit}")
    
    # Example 2: PHP Error
    print("\n2. PHP Error")
    print("-" * 40)
    php_error = """
    Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given 
    in /var/www/html/login.php on line 42
    """
    analysis2 = ml_engine.analyze_error_message(php_error)
    print(f"Error Type: {analysis2.error_type}")
    print(f"Confidence: {analysis2.confidence:.2%}")
    print(f"Extracted Info: {analysis2.extracted_info}")
    print(f"Hints:")
    for hint in analysis2.hints:
        print(f"  - {hint}")
    
    # Example 3: Python/Jinja2 Error
    print("\n3. Python/Jinja2 Error")
    print("-" * 40)
    python_error = """
    Traceback (most recent call last):
      File "/app/views.py", line 23, in render_template
        return template.render(data)
    jinja2.exceptions.UndefinedError: 'user' is undefined
    """
    analysis3 = ml_engine.analyze_error_message(python_error)
    print(f"Error Type: {analysis3.error_type}")
    print(f"Confidence: {analysis3.confidence:.2%}")
    print(f"Extracted Info: {analysis3.extracted_info}")
    print(f"Suggested Exploits:")
    for exploit in analysis3.suggested_exploits:
        print(f"  - {exploit}")
    
    # Example 4: Command Injection Error
    print("\n4. Command Injection Error")
    print("-" * 40)
    cmd_error = "sh: 1: curl: command not found"
    analysis4 = ml_engine.analyze_error_message(cmd_error)
    print(f"Error Type: {analysis4.error_type}")
    print(f"Confidence: {analysis4.confidence:.2%}")
    print(f"Hints:")
    for hint in analysis4.hints:
        print(f"  - {hint}")


def demo_attack_vector_ranking():
    """Demonstrate attack vector ranking"""
    print("\n\n" + "=" * 80)
    print("ATTACK VECTOR RANKING DEMO")
    print("=" * 80)
    
    ml_engine = MLEngine()
    
    # Create various attack vectors
    vectors = [
        AttackVector(
            module_name="sql_injection",
            vulnerability_type="sql_injection",
            description="Test for SQL injection vulnerabilities",
            estimated_time=120.0,
            complexity="medium"
        ),
        AttackVector(
            module_name="xss",
            vulnerability_type="xss",
            description="Test for cross-site scripting",
            estimated_time=60.0,
            complexity="low"
        ),
        AttackVector(
            module_name="command_injection",
            vulnerability_type="command_injection",
            description="Test for command injection",
            estimated_time=90.0,
            complexity="medium"
        ),
        AttackVector(
            module_name="ssti",
            vulnerability_type="ssti",
            description="Test for server-side template injection",
            estimated_time=150.0,
            complexity="high"
        ),
        AttackVector(
            module_name="xxe",
            vulnerability_type="xxe",
            description="Test for XML external entity injection",
            estimated_time=100.0,
            complexity="medium"
        ),
        AttackVector(
            module_name="ssrf",
            vulnerability_type="ssrf",
            description="Test for server-side request forgery",
            estimated_time=80.0,
            complexity="low"
        )
    ]
    
    # Rank without context
    print("\n1. Ranking without context (default)")
    print("-" * 40)
    ranked1 = ml_engine.rank_attack_vectors(vectors, {})
    for r in ranked1:
        print(f"\nRank {r.rank}: {r.vector.module_name}")
        print(f"  Exploitation Probability: {r.exploitation_probability:.2%}")
        print(f"  Time to Flag: {r.time_to_flag:.1f}s")
        print(f"  Score: {r.score:.3f}")
        print(f"  Complexity: {r.vector.complexity}")
    
    # Rank with PHP/MySQL context
    print("\n\n2. Ranking with PHP/MySQL context")
    print("-" * 40)
    context = {"technologies": ["PHP", "MySQL", "Apache"]}
    ranked2 = ml_engine.rank_attack_vectors(vectors, context)
    for r in ranked2[:3]:  # Top 3
        print(f"\nRank {r.rank}: {r.vector.module_name}")
        print(f"  Exploitation Probability: {r.exploitation_probability:.2%}")
        print(f"  Time to Flag: {r.time_to_flag:.1f}s")
        print(f"  Score: {r.score:.3f}")


def demo_adaptive_learning():
    """Demonstrate adaptive learning"""
    print("\n\n" + "=" * 80)
    print("ADAPTIVE LEARNING DEMO")
    print("=" * 80)
    
    ml_engine = MLEngine()
    
    target_url = "https://example.com/login"
    
    # Simulate several attack attempts
    print("\n1. Recording Attack Attempts")
    print("-" * 40)
    
    attempts_results = [
        # Successful SQL injection
        (
            AttackAttempt(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                target_url=target_url,
                payload="' OR '1'='1",
                timestamp=datetime.now(),
                parameters={"username": "admin"}
            ),
            AttackResult(
                success=True,
                vulnerability_found=True,
                response_time=0.5,
                status_code=200,
                flags_found=["CTF{sql_injection_success}"]
            )
        ),
        # Failed XSS attempt
        (
            AttackAttempt(
                module_name="xss",
                vulnerability_type="xss",
                target_url=target_url,
                payload="<script>alert(1)</script>",
                timestamp=datetime.now()
            ),
            AttackResult(
                success=False,
                vulnerability_found=False,
                response_time=0.3,
                status_code=200,
                error_message="Blocked by WAF"
            )
        ),
        # Another successful SQL injection
        (
            AttackAttempt(
                module_name="sql_injection",
                vulnerability_type="sql_injection",
                target_url=target_url,
                payload="' UNION SELECT NULL--",
                timestamp=datetime.now()
            ),
            AttackResult(
                success=True,
                vulnerability_found=True,
                response_time=0.6,
                status_code=200,
                flags_found=["CTF{union_based_sqli}"]
            )
        ),
        # Failed command injection
        (
            AttackAttempt(
                module_name="command_injection",
                vulnerability_type="command_injection",
                target_url=target_url,
                payload="; ls -la",
                timestamp=datetime.now()
            ),
            AttackResult(
                success=False,
                vulnerability_found=False,
                response_time=0.4,
                status_code=403
            )
        )
    ]
    
    for attempt, result in attempts_results:
        ml_engine.learn_from_attempt(attempt, result)
        status = "SUCCESS" if result.success else "FAILED"
        print(f"{status}: {attempt.vulnerability_type} - {attempt.payload[:30]}...")
    
    # Get adaptive strategy for SQL injection
    print("\n\n2. Adaptive Strategy for SQL Injection")
    print("-" * 40)
    strategy_sql = ml_engine.get_adaptive_strategy(target_url, "sql_injection")
    print(f"Strategy: {strategy_sql['strategy']}")
    print(f"Success Rate: {strategy_sql['success_rate']:.2%}")
    print(f"Total Attempts: {strategy_sql['total_attempts']}")
    print(f"Recommendations:")
    for rec in strategy_sql['recommendations']:
        print(f"  - {rec}")
    if strategy_sql['adjustments']:
        print(f"Adjustments:")
        for key, value in strategy_sql['adjustments'].items():
            if isinstance(value, list):
                print(f"  - {key}: {len(value)} items")
            else:
                print(f"  - {key}: {value}")
    
    # Get adaptive strategy for XSS
    print("\n\n3. Adaptive Strategy for XSS")
    print("-" * 40)
    strategy_xss = ml_engine.get_adaptive_strategy(target_url, "xss")
    print(f"Strategy: {strategy_xss['strategy']}")
    print(f"Success Rate: {strategy_xss['success_rate']:.2%}")
    print(f"Total Attempts: {strategy_xss['total_attempts']}")
    print(f"Recommendations:")
    for rec in strategy_xss['recommendations']:
        print(f"  - {rec}")
    if strategy_xss['adjustments']:
        print(f"Adjustments:")
        for key, value in strategy_xss['adjustments'].items():
            print(f"  - {key}: {value}")
    
    # Export learning data
    print("\n\n4. Export Learning Data")
    print("-" * 40)
    learning_data = ml_engine.export_learning_data()
    print(f"Success Patterns: {len(learning_data['success_patterns'])} vulnerability types")
    print(f"Failure Patterns: {len(learning_data['failure_patterns'])} vulnerability types")
    print(f"Attack History: {learning_data['attack_history_count']} attempts")
    
    # Show some patterns
    for vuln_type, patterns in learning_data['success_patterns'].items():
        if patterns:
            print(f"\n{vuln_type}: {len(patterns)} successful patterns")


def demo_integration_scenario():
    """Demonstrate a complete integration scenario"""
    print("\n\n" + "=" * 80)
    print("INTEGRATION SCENARIO: CTF Challenge Analysis")
    print("=" * 80)
    
    ml_engine = MLEngine()
    
    # Step 1: Initial reconnaissance
    print("\nStep 1: Initial Reconnaissance")
    print("-" * 40)
    target = TargetInfo(
        url="https://ctf.example.com/challenge",
        technologies=["Python", "Flask", "Jinja2", "SQLite"],
        frameworks=["Flask"],
        server_software="Werkzeug/2.0.1",
        response_headers={"X-Powered-By": "Flask"},
        error_messages=[
            "jinja2.exceptions.UndefinedError: 'user' is undefined",
            "sqlite3.OperationalError: near \"'\": syntax error"
        ],
        detected_language="python",
        has_javascript=True
    )
    
    # Step 2: Predict vulnerabilities
    print("\nStep 2: Vulnerability Predictions")
    print("-" * 40)
    predictions = ml_engine.predict_vulnerabilities(target)
    print(f"Found {len(predictions)} potential vulnerabilities:\n")
    for i, pred in enumerate(predictions[:3], 1):
        print(f"{i}. {pred.vulnerability_type.upper()}")
        print(f"   Confidence: {pred.confidence:.2%}")
        print(f"   Reasoning: {pred.reasoning}\n")
    
    # Step 3: Analyze errors
    print("\nStep 3: Error Message Analysis")
    print("-" * 40)
    for error in target.error_messages:
        analysis = ml_engine.analyze_error_message(error)
        print(f"\nError: {error[:60]}...")
        print(f"Type: {analysis.error_type}")
        print(f"Top Exploit: {analysis.suggested_exploits[0] if analysis.suggested_exploits else 'N/A'}")
    
    # Step 4: Rank attack vectors
    print("\n\nStep 4: Attack Vector Ranking")
    print("-" * 40)
    vectors = [
        AttackVector(
            module_name="ssti",
            vulnerability_type="ssti",
            description="Jinja2 SSTI",
            estimated_time=120.0,
            complexity="medium"
        ),
        AttackVector(
            module_name="sql_injection",
            vulnerability_type="sql_injection",
            description="SQLite injection",
            estimated_time=90.0,
            complexity="low"
        ),
        AttackVector(
            module_name="xss",
            vulnerability_type="xss",
            description="Reflected XSS",
            estimated_time=60.0,
            complexity="low"
        )
    ]
    
    context = {"technologies": ["Python", "Flask", "Jinja2", "SQLite"]}
    ranked = ml_engine.rank_attack_vectors(vectors, context)
    
    print("\nRecommended Attack Order:")
    for r in ranked:
        print(f"\n{r.rank}. {r.vector.module_name.upper()}")
        print(f"   Probability: {r.exploitation_probability:.2%}")
        print(f"   Est. Time: {r.time_to_flag:.0f}s")
        print(f"   Score: {r.score:.3f}")
    
    print("\n\nRecommendation: Start with SSTI testing on Jinja2 templates!")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("ML ENGINE DEMONSTRATION")
    print("=" * 80)
    
    demo_vulnerability_prediction()
    demo_error_analysis()
    demo_attack_vector_ranking()
    demo_adaptive_learning()
    demo_integration_scenario()
    
    print("\n\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
