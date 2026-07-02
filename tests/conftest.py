"""Make `import app` work no matter where pytest is invoked from.

The tests import the dashboard module and exercise its pure functions
(validators, parsers, protection guards). Importing `app` is side-effect-free:
it defines the Flask app and helpers but never calls ensure_bootstrap()/app.run()
(those live under `if __name__ == '__main__'`).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
