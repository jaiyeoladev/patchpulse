import sys

from .app import SPEC
from .core.cli import main

sys.exit(main(SPEC))
