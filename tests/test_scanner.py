import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.scanner import analyze_url, score_to_grade, score_to_color


class TestScoreToGrade:
    def test_grade_a(self):
        assert score_to_grade(95) == 'A'
        assert score_to_grade(90) == 'A'

    def test_grade_b(self):
        assert score_to_grade(80) == 'B'
        assert score_to_grade(75) == 'B'

    def test_grade_c(self):
        assert score_to_grade(70) == 'C'
        assert score_to_grade(60) == 'C'

    def test_grade_d(self):
        assert score_to_grade(55) == 'D'
        assert score_to_grade(40) == 'D'

    def test_grade_f(self):
        assert score_to_grade(30) == 'F'
        assert score_to_grade(0) == 'F'


class TestScoreToColor:
    def test_green_above_75(self):
        assert score_to_color(90) == 'green'
        assert score_to_color(75) == 'green'

    def test_orange_between_50_and_74(self):
        assert score_to_color(60) == 'orange'
        assert score_to_color(50) == 'orange'

    def test_red_below_50(self):
        assert score_to_color(49) == 'red'
        assert score_to_color(0) == 'red'


class TestAnalyzeUrl:
    def test_returns_dict_with_required_keys(self):
        result = analyze_url('https://example.com')
        assert isinstance(result, dict)
        assert 'score' in result
        assert 'checks' in result
        assert 'tickets' in result
        assert 'url' in result

    def test_score_is_between_0_and_100(self):
        result = analyze_url('https://example.com')
        assert 0 <= result['score'] <= 100

    def test_invalid_url_returns_error(self):
        result = analyze_url('http://this-url-definitely-does-not-exist-xyz-123.com')
        assert result['score'] <= 50

    def test_https_url_does_not_lose_https_points(self):
        result = analyze_url('https://google.com')
        # Google utilise HTTPS donc on ne perd pas les 30 points HTTPS
        assert result['score'] >= 70