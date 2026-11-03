import os, runpy
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "server"))
runpy.run_path("server.py", run_name="__main__")
