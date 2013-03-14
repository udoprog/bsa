import os
import sys
import logging

from bsa.utils import default_file_reader


log = logging.getLogger(__name__)


def build_path(root_directory, path, last_path, fake_root):
    """
    There are three ways to build an inclusion path.

    1) An absolute path is specified, in which case it should be assumed
       that the real referred path is relative from the fake_directory.
    2) Check if the file is an actual file from the root directory, in that
       case, it's what we are looking for.
    3) Assume that the file is relative to the last included file.
    """

    if os.path.isabs(path):
        return os.path.join(
            root_directory,
            os.path.relpath(
                path,
                fake_root))

    from_root = os.path.join(root_directory, path)

    # if path directly in root directory
    if os.path.isfile(from_root):
        return from_root

    last_directory = os.path.dirname(last_path)

    # relative to previously parsed file.
    return os.path.join(last_directory, path)


class IncludeState(object):
    """
    A class that keeps track of the current state of the include handler to
    supply some late functionality.
    """

    __slots__ = ("root_directory", "last_path", "fake_root")

    def __init__(self, root_directory, last_path, fake_root):
        self.root_directory = root_directory
        self.last_path = last_path
        self.fake_root = fake_root

    def build_path(self, path):
        return build_path(self.root_directory, path, self.last_path,
                          self.fake_root)


class IncludeStack(object):
    """
    Stack implementation for IncludeHandler.

    This is exposed to allow for external components to integrate with the
    IncludeHandler.
    """

    def push_stack(self, path):
        """
        Push an element on top of the stack.
        """
        raise NotImplementedError()

    def pop_stack(self):
        """
        Remove and return the last element on the stack.
        """
        raise NotImplementedError()

    def peek_stack(self):
        """
        Peek at the last element, but do not remove it.
        """
        raise NotImplementedError()


class DefaultStack(IncludeStack):
    def __init__(self):
        self.stack = list()

    def push_stack(self, path):
        self.stack.append(path)

    def pop_stack(self):
        return self.stack.pop()

    def peek_stack(self):
        return self.stack[-1]

    def __repr__(self):
        return "<DefaultStack stack={self.stack!r}>".format(self=self)


class IncludeHandler(object):
    """
    Handles inclusion in pyparsing by bootstrapping a specific part of
    the grammar against the content of a new file.
    """

    def __init__(self,
                 root_directory,
                 path,
                 parser,
                 fake_root=None,
                 file_reader=None,
                 stack=None):

        self.root_directory = os.path.abspath(root_directory)

        if fake_root is None:
            fake_root = os.getcwd()

        if file_reader is None:
            self.file_reader = default_file_reader
        else:
            self.file_reader = file_reader

        if stack is None:
            self.stack = DefaultStack()
        else:
            self.stack = stack

        # cache ASTs to improve performance.
        self.result_cache = dict()

        self.stack.push_stack(path)

        # the simulated current working directory
        self.fake_root = fake_root

        self.parser = parser

    def build_path(self, path):
        last_path = self.stack.peek_stack()
        root_directory = self.root_directory
        fake_root = self.fake_root
        return build_path(root_directory, path, last_path, fake_root)

    def _include(self, path):
        path = self.build_path(path)

        # signal stack change to stack component.
        self.stack.push_stack(path)

        cached_value = self.result_cache.get(path)

        if cached_value is not None:
            return cached_value

        try:
            with self.file_reader(self.root_directory, path) as f:
                result = self.parser.parse_file(f)
        except:
            logging.error("could not parse: {0}".format(path),
                          exc_info=sys.exc_info())
            raise

        self.result_cache[path] = result

        self.stack.pop_stack()

        return result

    def include(self, path):
        """
        External interface to actually including a path.
        """

        last_path = self.stack.peek_stack()

        try:
            return self._include(path)
        except:
            log.error("{0}: error during include".format(last_path),
                      exc_info=sys.exc_info())
            raise

    def __call__(self, path):
        return self.include(path)

    def pyparsing_call(self, s, l, t):
        return self.include(t[0])

    def pyparsing_mark(self, s, l, t):
        last_path = self.stack.peek_stack()
        state = IncludeState(self.root_directory, last_path, self.fake_root)
        return tuple([state] + list(t))


__all__ = [
    "IncludeStack",
    "IncludeHandler"
]
