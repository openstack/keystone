#TODO (India Team) Need to modify this script
import logging
import os
import unittest

MODULE_EXTENSIONS = set('.py .pyc .pyo'.split())


def unit_test_extractor(tup, path, filenames):
    """Pull ``unittest.TestSuite``s from modules in path
    if the path represents a valid Python package. Accumulate
    results in `tup[1]`.
    """
    package_path, suites = tup
    logging.debug('Path: %s', path)
    logging.debug('Filenames: %s', filenames)
    relpath = os.path.relpath(path, package_path)
    relpath_pieces = relpath.split(os.sep)

    if relpath_pieces[0] == '.':  # Base directory.
        relpath_pieces.pop(0)  # Otherwise, screws up module name.
    elif not any(os.path.exists(os.path.join(path, '__init__' + ext))
            for ext in MODULE_EXTENSIONS):
        return  # Not a package directory and not the base directory, reject.

    logging.info('Base: %s', '.'.join(relpath_pieces))
    for filename in filenames:
        base, ext = os.path.splitext(filename)
        if ext not in MODULE_EXTENSIONS:  # Not a Python module.
            continue
        logging.info('Module: %s', base)
        module_name = '.'.join(relpath_pieces + [base])
        logging.info('Importing from %s', module_name)
        module = __import__(module_name)
        module_suites = unittest.defaultTestLoader.loadTestsFromModule(module)
        logging.info('Got suites: %s', module_suites)
        suites += module_suites


def get_test_suites(path):
    """:return: Iterable of suites for the packages/modules
    present under :param:`path`.
    """
    logging.info('Base path: %s', package_path)
    suites = []
    os.path.walk(package_path, unit_test_extractor, (package_path, suites))
    logging.info('Got suites: %s', suites)
    return suites

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN)
    package_path = os.path.dirname(os.path.abspath(__file__))
    suites = get_test_suites(package_path)
    for suite in suites:
        unittest.TextTestRunner(verbosity=2).run(suite)
