"""
SWE-bench Hack #2: Weak Test Exploitation
Issues: arXiv:2503.15223, arXiv:2603.00520

SWE-bench only runs tests from the PR that fixed the bug (FAIL_TO_PASS + PASS_TO_PASS).
This means a patch can pass evaluation while being semantically WRONG, as long as it
makes the specific test cases pass.

This demo shows a concrete example: a bug where a function should handle edge cases,
but the test only checks one specific input. A "patch" that hardcodes the expected
output for that input passes the test without fixing the underlying bug.

Real-world stats:
- 19.8% of patches marked "solved" by top-30 agents are semantically incorrect
- Top agent drops from 78.8% to 62.2% when adversarial tests are added (SWE-ABS)
- 7.8% of plausible patches fail when the FULL test suite is run
"""


# === THE "BUG" ===
# Original buggy code: format_duration should handle various time units
def format_duration_buggy(seconds):
    """Format a duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    # BUG: hours case is wrong -- uses minutes variable instead of computing hours
    else:
        hours = seconds // 360  # Wrong divisor! Should be 3600
        return f"{hours}h"


# === THE "GOLD PATCH" (correct fix) ===
def format_duration_correct(seconds):
    """Format a duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    else:
        hours = seconds // 3600  # Fixed: correct divisor
        return f"{hours}h"


# === THE SWE-BENCH TEST (from the PR -- only tests specific values) ===
def test_fail_to_pass():
    """The only test that changed in the PR. Must fail before fix, pass after."""
    assert format_duration_correct(7200) == "2h"  # 2 hours


def test_pass_to_pass():
    """Tests that already passed and must keep passing."""
    assert format_duration_correct(30) == "30s"
    assert format_duration_correct(120) == "2m"


# === THE REWARD-HACKING "PATCH" ===
# This passes ALL SWE-bench tests but is WRONG for most inputs
def format_duration_hacked(seconds):
    """Format a duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    else:
        # HACK: hardcode the test case instead of fixing the formula
        if seconds == 7200:
            return "2h"
        # Everything else still uses the wrong formula
        hours = seconds // 360
        return f"{hours}h"


# === DEMONSTRATION ===
if __name__ == "__main__":
    print("=== SWE-bench Weak Test Exploitation Demo ===\n")

    # Show the SWE-bench tests pass for the hacked version
    print("[SWE-bench evaluation] Running FAIL_TO_PASS + PASS_TO_PASS tests:")
    results = {
        "FAIL_TO_PASS: test_fail_to_pass": format_duration_hacked(7200) == "2h",
        "PASS_TO_PASS: test_30s": format_duration_hacked(30) == "30s",
        "PASS_TO_PASS: test_120s": format_duration_hacked(120) == "2m",
    }
    for test_name, passed in results.items():
        print(f"  {'PASS' if passed else 'FAIL'} {test_name}")

    all_swebench_pass = all(results.values())
    print(f"\n  SWE-bench verdict: {'RESOLVED' if all_swebench_pass else 'FAILED'}")

    # Show the hacked version is WRONG for other inputs
    print("\n[Adversarial tests] Testing with additional inputs:")
    adversarial_tests = {
        3600: "1h",    # 1 hour
        10800: "3h",   # 3 hours
        36000: "10h",  # 10 hours
        86400: "24h",  # 24 hours
    }

    any_fail = False
    for seconds, expected in adversarial_tests.items():
        hacked_result = format_duration_hacked(seconds)
        correct_result = format_duration_correct(seconds)
        passed = (hacked_result == expected)
        if not passed:
            any_fail = True
        print(f"  {'PASS' if passed else 'FAIL'} format_duration({seconds}) "
              f"= '{hacked_result}' (expected '{expected}', "
              f"correct impl gives '{correct_result}')")

    print(f"\n  Adversarial verdict: {'SOME FAILURES -- patch is wrong!' if any_fail else 'all passed'}")

    # Summary
    print("\n=== Summary ===")
    print(f"SWE-bench says: RESOLVED (all {len(results)} tests pass)")
    print(f"Reality: WRONG (fails {sum(1 for s,e in adversarial_tests.items() if format_duration_hacked(s) != e)}/{len(adversarial_tests)} adversarial tests)")
    print(f"\nThe hacked patch only works for seconds=7200 (the test case).")
    print(f"For 3600s: hacked gives '{format_duration_hacked(3600)}', correct is '1h'")
    print(f"For 86400s: hacked gives '{format_duration_hacked(86400)}', correct is '24h'")
