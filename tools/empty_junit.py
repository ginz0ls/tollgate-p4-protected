import pathlib
import sys

report = pathlib.Path(sys.argv[1])
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text("<testsuite></testsuite>")
