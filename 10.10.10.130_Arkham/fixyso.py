#!/usr/bin/env python3
import subprocess
import re
import sys

YSOSERIAL_PATH = "ysoserial-all.jar"  # https://github.com/frohoff/ysoserial/releases
JAVA_COMMAND = ["java"]  # May be eg. ["java", "-Xmx2g"] or a path to a java binary

def extract_missing(error):
    match = re.findall(r'java\.lang\.reflect\.InaccessibleObjectException: .*?: module (.*?) does not "opens (.*?)" to unnamed module @', error)
    if match: return "InaccessibleObjectException", match[0]
    match = re.findall(r'java\.lang\.IllegalAccessError: .*? because module (.*?) does not export (.*?) to unnamed module @', error)
    if match: return "IllegalAccessError", match[0]
    
    return None, (None, None)

def run(args, java_prefix=JAVA_COMMAND, ysoserial=YSOSERIAL_PATH):
    try:
        # Run while capturing stderr
        subprocess.run(java_prefix + ["-jar", ysoserial, *args], stdout=sys.stdout.buffer, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as e:
        error = e.stderr.decode()
        exception, (module, package) = extract_missing(error)
        # Fix error if possible
        if module and package:
            print(f"Fixing {exception}: '{module}/{package}'", file=sys.stderr)
            java_prefix += ["--add-opens", f"{module}/{package}=ALL-UNNAMED"]
            run(args, java_prefix=java_prefix)  # Run again
        else:  # Just print any other error
            print(error, file=sys.stderr)

if __name__ == "__main__":
    run(sys.argv[1:])

# ./ysoserial-fix.py URLDNS "http://example.com"
