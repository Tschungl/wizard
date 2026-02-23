# main.py
import os, sys

def main():
    if os.geteuid() != 0:
        print("ERROR: This wizard must be run as root.", file=sys.stderr)
        sys.exit(1)
    from app import AsimilyWizard
    AsimilyWizard().run()
    sys.exit(0)

if __name__ == "__main__":
    main()
