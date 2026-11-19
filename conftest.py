import sys
from pathlib import Path

# Allow `pytest` from a bare clone: the package lives under src/ and is not
# importable until installed. Test imports of shield_mcp work either way.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
