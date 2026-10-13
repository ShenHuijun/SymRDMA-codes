"""`python3 tests/scripts/symtest/__main__.py <cmd>` 直接执行入口。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symtest.cli import main

if __name__ == "__main__":
    sys.exit(main())
