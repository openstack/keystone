"""
Searches the given path for JSON files, and validates their contents.

Optionally, replaces valid JSON files with their pretty-printed
counterparts.
"""

import argparse
import collections
import errno
import json
import logging
import os
import re


# Configure logging
logging.basicConfig(format='%(levelname)s: %(message)s')

# Configure commandlineability
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('-p', type=str, required=False, default='.',
    help='the path to search for JSON files', dest='path')
parser.add_argument('-r', type=str, required=False, default='.json$',
    help='the regular expression to match filenames against ' \
        '(not absolute paths)', dest='regexp')
parser.add_argument('-b', required=False, action='store_true',
    default=False, help='beautify valid JSON (replaces file contents)',
    dest='beautify')
args = parser.parse_args()


def main():
    files = find_matching_files(args.path, args.regexp)

    results = True
    for path in files:
        results &= validate_json(path)

    # Invert our test results to produce a status code
    exit(not results)


def beautify(path, ordered_dict):
    """Replaces the given file with pretty-printed JSON"""
    # convert dict to str, preserving original key order
    new_contents = json.dumps(ordered_dict, sort_keys=False, indent=2)

    # json.dump adds a trailing space
    new_contents = new_contents.replace(' \n', '\n')

    # json.dumps doesn't include a newline, for obvious reasons
    new_contents += "\n"

    return replace_file(path, new_contents)


def validate_json(path):
    """Open a file and validate it's contents as JSON"""
    try:
        contents = read_file(path)

        if contents is False:
            logging.warning('Insufficient permissions to open: %s' % path)
            return False
    except:
        logging.warning('Unable to open: %s' % path)
        return False

    try:
        ordered_dict = json.loads(contents,
            object_pairs_hook=collections.OrderedDict)
    except:
        logging.error('Unable to parse: %s' % path)
        return False

    if args.beautify:
        beautify(path, ordered_dict)

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
    """Attempt to read a file safely

    Returns the contents of the file as a string on success, False otherwise"""
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


def replace_file(path, new_contents):
    """Overwrite the file at the given path with the new contents

    Returns True on success, False otherwise."""
    try:
        f = open(path, 'w')
        f.write(new_contents)
        f.close()
    except:
        logging.error('Unable to write: %s' % f)
        return False
    return True


if __name__ == "__main__":
    main()
