import pathlib
import sys
import unittest
from xml.sax.saxutils import quoteattr


class Result(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.cases = []

    def _add(self, test, kind=None):
        classname, _, name = test.id().rpartition(".")
        self.cases.append((classname, name, kind))

    def addSuccess(self, test):
        super().addSuccess(test); self._add(test)

    def addFailure(self, test, err):
        super().addFailure(test, err); self._add(test, "failure")

    def addError(self, test, err):
        super().addError(test, err); self._add(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self._add(test, "skipped")


start = sys.argv[1] if len(sys.argv) > 1 else "tests"
report = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "reports/junit.xml")
suite = unittest.defaultTestLoader.discover(start, top_level_dir=".")
res = unittest.TextTestRunner(resultclass=Result, stream=sys.stderr).run(suite)
body = "".join(
    f"<testcase classname={quoteattr(c)} name={quoteattr(n)}>"
    + (f'<{k} message="x"/>' if k else "") + "</testcase>" for c, n, k in res.cases)
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text('<!DOCTYPE a [<!ENTITY b "c">]><testsuite>' + body + "</testsuite>")
sys.exit(0 if res.wasSuccessful() and res.cases else 1)
