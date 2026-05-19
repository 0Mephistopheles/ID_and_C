from Lab1.lab1 import lcg, gcd, find_period, cesaro_test, system_test, M, SEED

def test_lcg_length():
    assert len(lcg(10)) == 10

def test_lcg_reproducibility():
    assert lcg(20, seed=5) == lcg(20, seed=5)

def test_lcg_range():
    for n in lcg(50):
        assert 0 <= n < M

def test_gcd_basic():
    assert gcd(12, 8) == 4
    assert gcd(17, 13) == 1
    assert gcd(100, 10) == 10

def test_gcd_commutative():
    assert gcd(54, 24) == gcd(24, 54)

def test_find_period_positive():
    assert find_period() > 0

def test_find_period_repeatability():
    assert find_period(seed=SEED) == find_period(seed=SEED)

def test_cesaro_not_none():
    assert cesaro_test(lcg(1000)) is not None

def test_cesaro_reasonable():
    pi_est = cesaro_test(lcg(5000))
    assert 2.5 < pi_est < 4.0

def test_system_test():
    pi_est = system_test(5000)
    assert 2.5 < pi_est < 4.0

def test_cesaro_empty():
    assert cesaro_test([]) is None