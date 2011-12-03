import unittest2 as unittest
import sys

from keystone.tools import buffout


class TestStdoutIdentity(unittest.TestCase):
    """Tests buffout's manipulation of the stdout pointer"""
    def test_stdout(self):
        stdout = sys.stdout
        ob = buffout.OutputBuffer()
        self.assertTrue(sys.stdout is stdout,
                "sys.stdout was replaced")
        ob.start()
        self.assertTrue(sys.stdout is not stdout,
                "sys.stdout not replaced")
        ob.stop()
        self.assertTrue(sys.stdout is stdout,
                "sys.stdout not restored")


class TestOutputBufferContents(unittest.TestCase):
    """Tests the contents of the buffer"""
    def test_read_contents(self):
        with buffout.OutputBuffer() as ob:
            print 'foobar'
            print 'wompwomp'
            output = ob.read()
            self.assertEquals(len(output), 16, output)
            self.assertIn('foobar', output)
            self.assertIn('ompwom', output)

    def test_read_lines(self):
        with buffout.OutputBuffer() as ob:
            print 'foobar'
            print 'wompwomp'
            lines = ob.read_lines()
            self.assertTrue(isinstance(lines, list))
            self.assertEqual(len(lines), 2)
            self.assertIn('foobar', lines)
            self.assertIn('wompwomp', lines)

    def test_additional_output(self):
        with buffout.OutputBuffer() as ob:
            print 'foobar'
            lines = ob.read_lines()
            self.assertEqual(len(lines), 1)
            print 'wompwomp'
            lines = ob.read_lines()
            self.assertEqual(len(lines), 2)

    def test_clear(self):
        with buffout.OutputBuffer() as ob:
            print 'foobar'
            ob.clear()
            print 'wompwomp'
            output = ob.read()
            self.assertNotIn('foobar', output)
            self.assertIn('ompwom', output)

    def test_buffer_preservation(self):
        ob = buffout.OutputBuffer()
        ob.start()

        print 'foobar'
        print 'wompwomp'

        ob.stop()

        output = ob.read()
        self.assertIn('foobar', output)
        self.assertIn('ompwom', output)

    def test_buffer_contents(self):
        ob = buffout.OutputBuffer()
        ob.start()

        print 'foobar'
        print 'wompwomp'

        ob.stop()

        self.assertEqual('foobar\nwompwomp\n', unicode(ob))
        self.assertEqual('foobar\nwompwomp\n', str(ob))

    def test_exception_raising(self):
        def raise_value_error():
            with buffout.OutputBuffer():
                raise ValueError()

        self.assertRaises(ValueError, raise_value_error)
