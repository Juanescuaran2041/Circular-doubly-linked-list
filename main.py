import argparse

from mtd_ring.api.server import run


# Reads the command line options.
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mirage Ring: a moving target of honeypots.")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="preferred port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    parser.add_argument(
        "--stateless", action="store_true", help="keep no state on the server, like the Vercel deployment"
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_arguments()
    run(arguments.host, arguments.port, open_browser=not arguments.no_browser, stateless=arguments.stateless)
