#!/usr/bin/env python3
"""
Race Condition Module Demo

This script demonstrates the race condition testing capabilities
of the VulnChain framework.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.modules.race_condition import (
    RaceConditionTester,
    RaceConditionTest,
    TimingStrategy,
    RaceConditionType,
)
from app.core.request_handler import RequestHandler
from app.core.config import Config


async def demo_basic_race_condition():
    """Demo: Basic race condition testing"""
    print("=" * 60)
    print("Demo 1: Basic Race Condition Testing")
    print("=" * 60)
    
    # Initialize components
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=20)
    
    # Configure test for a hypothetical vulnerable endpoint
    test = RaceConditionTest(
        url="https://httpbin.org/delay/1",  # Simulated endpoint
        method="GET",
        num_requests=10,
        timing_strategy=TimingStrategy.SIMULTANEOUS,
    )
    
    print(f"\nTesting: {test.url}")
    print(f"Method: {test.method}")
    print(f"Requests: {test.num_requests}")
    print(f"Strategy: {test.timing_strategy.value}")
    
    # Run test
    result = await tester.test_race_condition(test)
    
    print(f"\nResults:")
    print(f"  Vulnerable: {result.is_vulnerable}")
    print(f"  Confidence: {result.confidence:.2f}")
    print(f"  Responses: {len(result.responses)}")
    
    if result.timing_data:
        print(f"\nTiming Data:")
        print(f"  Strategy: {result.timing_data.get('strategy')}")
        print(f"  Total time: {result.timing_data.get('total_time', 0):.3f}s")
        print(f"  Time spread: {result.timing_data.get('time_spread', 0) * 1000:.2f}ms")
    
    if result.evidence:
        print(f"\nEvidence:")
        for evidence in result.evidence:
            print(f"  - {evidence}")
    
    print()


async def demo_timing_strategies():
    """Demo: Different timing strategies"""
    print("=" * 60)
    print("Demo 2: Timing Strategies Comparison")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=20)
    
    strategies = [
        TimingStrategy.SIMULTANEOUS,
        TimingStrategy.STAGGERED,
        TimingStrategy.BURST,
        TimingStrategy.SYNCHRONIZED,
    ]
    
    url = "https://httpbin.org/get"
    
    for strategy in strategies:
        print(f"\n--- Testing {strategy.value} strategy ---")
        
        test = RaceConditionTest(
            url=url,
            method="GET",
            num_requests=10,
            timing_strategy=strategy,
            delay_microseconds=100 if strategy == TimingStrategy.STAGGERED else 0,
        )
        
        result = await tester.test_race_condition(test)
        
        print(f"Responses: {len(result.responses)}")
        if result.timing_data:
            print(f"Total time: {result.timing_data.get('total_time', 0):.3f}s")
            print(f"Time spread: {result.timing_data.get('time_spread', 0) * 1000:.2f}ms")
    
    print()


async def demo_custom_check_function():
    """Demo: Custom check function for specific race conditions"""
    print("=" * 60)
    print("Demo 3: Custom Check Function")
    print("=" * 60)
    
    def check_response_variation(responses):
        """Check if responses have significant variation"""
        if len(responses) < 2:
            return False
        
        # Check for status code variation
        status_codes = set(r.status_code for r in responses)
        if len(status_codes) > 1:
            print(f"  Custom check: Found {len(status_codes)} different status codes")
            return True
        
        # Check for body length variation
        body_lengths = set(len(r.text) for r in responses)
        if len(body_lengths) > 1:
            print(f"  Custom check: Found {len(body_lengths)} different body lengths")
            return True
        
        return False
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=15)
    
    test = RaceConditionTest(
        url="https://httpbin.org/uuid",  # Returns different UUID each time
        method="GET",
        num_requests=10,
        timing_strategy=TimingStrategy.SIMULTANEOUS,
        check_function=check_response_variation,
    )
    
    print(f"\nTesting: {test.url}")
    print(f"Using custom check function")
    
    result = await tester.test_race_condition(test)
    
    print(f"\nResults:")
    print(f"  Vulnerable: {result.is_vulnerable}")
    print(f"  Confidence: {result.confidence:.2f}")
    
    if result.evidence:
        print(f"\nEvidence:")
        for evidence in result.evidence:
            print(f"  - {evidence}")
    
    print()


async def demo_exploit_generation():
    """Demo: Exploit parameter generation"""
    print("=" * 60)
    print("Demo 4: Exploit Parameter Generation")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=20)
    
    # Simulate a vulnerable endpoint with custom check
    def simulate_vulnerability(responses):
        """Simulate finding a vulnerability"""
        # For demo purposes, consider it vulnerable if we got multiple responses
        return len(responses) >= 5
    
    test = RaceConditionTest(
        url="https://httpbin.org/post",
        method="POST",
        headers={"Content-Type": "application/json"},
        data={"action": "transfer", "amount": 100},
        num_requests=10,
        timing_strategy=TimingStrategy.SYNCHRONIZED,
        check_function=simulate_vulnerability,
    )
    
    print(f"\nTesting: {test.url}")
    print(f"Method: {test.method}")
    
    result = await tester.test_race_condition(test)
    
    print(f"\nResults:")
    print(f"  Vulnerable: {result.is_vulnerable}")
    
    if result.exploit_params:
        print(f"\nExploit Parameters:")
        print(f"  Optimal threads: {result.exploit_params.num_threads}")
        print(f"  Timing strategy: {result.exploit_params.timing_strategy.value}")
        print(f"  Success rate: {result.exploit_params.success_rate * 100:.1f}%")
        print(f"  Avg collision time: {result.exploit_params.avg_collision_time * 1000:.2f}ms")
        print(f"  Recommended attempts: {result.exploit_params.recommended_attempts}")
        
        print(f"\nExploit Code Preview (first 500 chars):")
        print("-" * 60)
        print(result.exploit_params.exploit_code[:500])
        print("...")
        print("-" * 60)
    
    print()


async def demo_toctou_detection():
    """Demo: TOCTOU vulnerability detection"""
    print("=" * 60)
    print("Demo 5: TOCTOU Vulnerability Detection")
    print("=" * 60)
    
    def check_toctou(responses):
        """Check for TOCTOU pattern: mix of success and failure"""
        status_codes = [r.status_code for r in responses]
        has_success = any(200 <= s < 300 for s in status_codes)
        has_failure = any(s >= 400 for s in status_codes)
        
        if has_success and has_failure:
            print(f"  TOCTOU pattern detected: {sum(1 for s in status_codes if 200 <= s < 300)} success, "
                  f"{sum(1 for s in status_codes if s >= 400)} failure")
            return True
        return False
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=20)
    
    test = RaceConditionTest(
        url="https://httpbin.org/status/200,400",  # Randomly returns 200 or 400
        method="GET",
        num_requests=20,
        timing_strategy=TimingStrategy.SIMULTANEOUS,
        check_function=check_toctou,
    )
    
    print(f"\nTesting: {test.url}")
    print(f"Looking for TOCTOU pattern (mix of success/failure)")
    
    result = await tester.test_race_condition(test)
    
    print(f"\nResults:")
    print(f"  Vulnerable: {result.is_vulnerable}")
    print(f"  Race type: {result.race_type.value if result.race_type else 'None'}")
    print(f"  Confidence: {result.confidence:.2f}")
    
    # Show status code distribution
    status_codes = [r.status_code for r in result.responses]
    print(f"\nStatus Code Distribution:")
    for code in sorted(set(status_codes)):
        count = status_codes.count(code)
        print(f"  {code}: {count} responses")
    
    print()


async def demo_adaptive_strategy():
    """Demo: Adaptive timing strategy"""
    print("=" * 60)
    print("Demo 6: Adaptive Timing Strategy")
    print("=" * 60)
    
    config = Config()
    request_handler = RequestHandler(config)
    tester = RaceConditionTester(request_handler, max_workers=25)
    
    test = RaceConditionTest(
        url="https://httpbin.org/delay/0.5",
        method="GET",
        num_requests=20,
        timing_strategy=TimingStrategy.ADAPTIVE,
    )
    
    print(f"\nTesting: {test.url}")
    print(f"Strategy: Adaptive (will adjust based on responses)")
    
    result = await tester.test_race_condition(test)
    
    print(f"\nResults:")
    print(f"  Responses: {len(result.responses)}")
    
    if result.timing_data:
        print(f"\nTiming Data:")
        print(f"  Final strategy: {result.timing_data.get('strategy')}")
        print(f"  Total time: {result.timing_data.get('total_time', 0):.3f}s")
        
        if 'batch_size' in result.timing_data:
            print(f"  Batch size: {result.timing_data.get('batch_size')}")
    
    print()


async def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("VulnChain Race Condition Module Demo")
    print("=" * 60 + "\n")
    
    demos = [
        ("Basic Race Condition Testing", demo_basic_race_condition),
        ("Timing Strategies", demo_timing_strategies),
        ("Custom Check Function", demo_custom_check_function),
        ("Exploit Generation", demo_exploit_generation),
        ("TOCTOU Detection", demo_toctou_detection),
        ("Adaptive Strategy", demo_adaptive_strategy),
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        try:
            await demo_func()
        except Exception as e:
            print(f"\nError in demo {i} ({name}): {e}")
            import traceback
            traceback.print_exc()
        
        if i < len(demos):
            print("\nPress Enter to continue to next demo...")
            input()
    
    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
