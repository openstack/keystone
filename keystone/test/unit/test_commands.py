import argparse
import logging
import unittest2 as unittest

from keystone.manage2.commands import version
from keystone.tools import buffout


LOGGER = logging.getLogger(__name__)


class CommandTestCase(unittest.TestCase):
    """Buffers stdout to test keystone-manage commands"""
    module = None
    stdout = None

    def setUp(self):
        # initialize the command module
        self.cmd = self.module.Command()

        # create an argparser for the module
        self.parser = argparse.ArgumentParser()
        version.Command.append_parser(self.parser)


class TestVersionCommand(CommandTestCase):
    """Tests for ./bin/keystone-manage version"""
    module = version

    API_VERSION = '2.0 beta'
    IMPLEMENTATION_VERSION = '2012.1-dev'

    def test_api_version(self):
        v = self.cmd.get_api_version()
        self.assertEqual(v, self.API_VERSION)

    def test_implementation_version(self):
        v = self.cmd.get_implementation_version()
        self.assertEqual(v, self.IMPLEMENTATION_VERSION)

    def test_no_args(self):
        with buffout.OutputBuffer() as ob:
            args = self.parser.parse_args([])
            self.cmd.run(args)
            lines = ob.read_lines()
            self.assertEqual(len(lines), 2, lines)
            self.assertIn(self.API_VERSION, lines[0])
            self.assertIn(self.IMPLEMENTATION_VERSION, lines[1])

    def test_api_arg(self):
        with buffout.OutputBuffer() as ob:
            args = self.parser.parse_args('--api'.split())
            self.cmd.run(args)
            lines = ob.read_lines()
            self.assertEqual(len(lines), 1, lines)
            self.assertIn(self.API_VERSION, lines[0])

    def test_implementation_arg(self):
        with buffout.OutputBuffer() as ob:
            args = self.parser.parse_args('--implementation'.split())
            self.cmd.run(args)
            lines = ob.read_lines()
            self.assertEqual(len(lines), 1, lines)
            self.assertIn(self.IMPLEMENTATION_VERSION, lines[0])
