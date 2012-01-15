import sys
import StringIO


class OutputBuffer():
    """Replaces stdout with a StringIO buffer"""

    def __init__(self):
        """Initialize output buffering"""
        # True if the OutputBuffer is started
        self.buffering = False

        # a reference to the current StringIO buffer
        self._buffer = None

        # stale if buffering is True; access buffer contents using .read()
        self._contents = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.stop()
        else:
            raise exc_type, exc_value, traceback

    def __unicode__(self):
        return self._contents

    def __str__(self):
        return str(self._contents)

    def start(self):
        """Replace stdout with a fresh buffer"""
        assert not self.buffering

        self.buffering = True
        self.old_stdout = sys.stdout

        self.clear()

    def read(self):
        """Read the current buffer"""
        if self.buffering:
            self._contents = self._buffer.getvalue()

        return self._contents

    def read_lines(self):
        """Returns the current buffer as a list

        Excludes the last line, which is empty.

        """
        return self.read().split("\n")[:-1]

    def clear(self):
        """Resets the current buffer"""
        assert self.buffering

        # dispose of the previous buffer, if any
        if self._buffer is not None:
            self._buffer.close()

        self._contents = ''
        self._buffer = StringIO.StringIO()
        sys.stdout = self._buffer

    def stop(self):
        """Stop buffering and pass the output along"""
        assert self.buffering

        # preserve the contents prior to closing the StringIO
        self.read()
        self._buffer.close()

        sys.stdout = self.old_stdout
        print self
        self.buffering = False

        return unicode(self)
