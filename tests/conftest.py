from pathlib import Path
import sys

# Allow tests to run when pytest is invoked from outside the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
