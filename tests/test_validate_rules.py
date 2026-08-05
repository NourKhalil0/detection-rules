import unittest
import tempfile
import os
from tools.validate_rules import validate_rule_file

class TestRuleValidator(unittest.TestCase):
    def setUp(self):
        self.valid_yaml = (
            "title: Test Rule\n"
            "id: 11111111-2222-3333-4444-555555555555\n"
            "status: experimental\n"
            "description: Test detection description\n"
            "author: Test Author\n"
            "logsource:\n  category: process_creation\n  product: windows\n"
            "detection:\n  selection:\n    Image: 'cmd.exe'\n  condition: selection\n"
            "level: high\n"
            "tags:\n  - attack.execution\n  - attack.t1059.003\n"
        )
        self.tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False, encoding='utf-8')
        self.tmp.write(self.valid_yaml)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def test_valid_rule(self):
        errors = validate_rule_file(self.tmp.name)
        self.assertEqual(len(errors), 0)

    def test_missing_field(self):
        invalid_yaml = "title: Incomplete Rule\nstatus: experimental\n"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False, encoding='utf-8') as f:
            f.write(invalid_yaml)
            fname = f.name
        try:
            errors = validate_rule_file(fname)
            self.assertTrue(any("Missing required field" in e for e in errors))
        finally:
            os.unlink(fname)

    def test_invalid_level(self):
        bad_level_yaml = self.valid_yaml.replace("level: high", "level: super_critical")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False, encoding='utf-8') as f:
            f.write(bad_level_yaml)
            fname = f.name
        try:
            errors = validate_rule_file(fname)
            self.assertTrue(any("Invalid level" in e for e in errors))
        finally:
            os.unlink(fname)

    def test_process_injection_rule_schema(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rule_path = os.path.join(base_dir, "rules", "sigma", "T1055_001_process_injection.yml")
        errors = validate_rule_file(rule_path)
        self.assertEqual(errors, [])

    def test_service_execution_rule_schema(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        rule_path = os.path.join(base_dir, "rules", "sigma", "T1569_002_service_execution.yml")
        errors = validate_rule_file(rule_path)
        self.assertEqual(errors, [])

if __name__ == '__main__':
    unittest.main()
