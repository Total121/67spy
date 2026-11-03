import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "server"))
os.chdir(os.path.join(os.path.dirname(__file__), "server"))
import server  # noqa: F401  — runs the app
