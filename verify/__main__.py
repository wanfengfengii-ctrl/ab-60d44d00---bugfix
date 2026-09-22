"""Allow ``python -m verify <package.zip>`` as the offline verifier."""
from .verify_package import main

if __name__ == "__main__":
    raise SystemExit(main())
