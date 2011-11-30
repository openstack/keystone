"""
Searches the given path for JSON files, and validates their contents.
"""

import argparse
import errno
import json
import logging
import os
import re


# Configure logging
logging.basicConfig(format='%(levelname)s: %(message)s')

# Configure commandlineability
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('-p --path', type=str, required=False,
    default='.', help='the path to search for JSON files',
    dest='path')
parser.add_argument('-r --regexp', type=str, required=False,
    default='.json$', help='the regex to look for',
    dest='regexp')
args = parser.parse_args()


def main():
    files = find_matching_files(args.path, args.regexp)

    results = True
    for path in files:
        results &= validate_json(path)

    # Invert our test results to produce a status code
    exit(not results)


def validate_json(path):
    """Open a file and validate it's contents as JSON"""
    try:
        contents = read_file(path)
    except:
        logging.warning('Unable to open: %s' % path)
        return False

    try:
        json.loads(contents)
    except:
        logging.error('Unable to parse: %s' % path)
        return False

    return True


def find_matching_files(path, pattern):
    """Search the given path for files matching the given pattern"""

    regex = re.compile(pattern)

    json_files = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if regex.search(name):
                full_name = os.path.join(root, name)
                json_files.append(full_name)
    return json_files


def read_file(path):
    """Attempt to read a file safely"""
    try:
        fp = open(path)
    except IOError as e:
        if e.errno == errno.EACCES:
            # permission error
            return False
        raise
    else:
        with fp:
            return fp.read()


if __name__ == "__main__":
    main()
