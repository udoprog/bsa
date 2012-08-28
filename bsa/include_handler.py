import os
import sys
import logging


log = logging.getLogger(__name__)


def build_path(path, last_path, root, fake_dir):
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
            root,
            os.path.relpath(
                path,
                fake_dir))

    from_root = os.path.join(root, path)

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

    __slots__ = ("last_path", "root", "fake_dir")

    def __init__(self, last_path, root, fake_dir):
        self.last_path = last_path
        self.root = root
        self.fake_dir = fake_dir

    def build_path(self, path):
        return build_path(path, self.last_path, self.root, self.fake_dir)


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


class IncludeHandler(object):
    """
    Handles inclusion in pyparsing by bootstrapping a specific part of
    the grammar against the content of a new file.
    """

    @classmethod
    def default_file_reader(cls, path):
        with open(path) as f:
            return f.read()

    def __init__(self,
                 path,
                 parser,
                 fake_dir=None,
                 file_reader=None,
                 stack=None):

        self.root = os.path.dirname(path)

        if fake_dir is None:
            fake_dir = os.getcwd()

        if file_reader is not None:
            self.file_reader = file_reader
        else:
            self.file_reader = self.default_file_reader

        if stack is None:
            self.stack = DefaultStack()
        else:
            self.stack = stack

        # cache ASTs to improve performance.
        self.result_cache = dict()

        self.stack.push_stack(path)

        # the simulated current working directory
        self.fake_dir = fake_dir

        self.parser = parser

    def build_path(self, path):
        last_path = self.stack.peek_stack()
        root = self.root
        fake_dir = self.fake_dir
        return build_path(path, last_path, root, fake_dir)

    def call_include(self, path):
        path = self.build_path(path)

        # signal stack change to stack component.
        self.stack.push_stack(path)

        cached_value = self.result_cache.get(path)

        if cached_value is not None:
            return cached_value

        file_contents = self.file_reader(path)

        try:
            result = self.parser.parseString(file_contents, parseAll=True)
        except:
            logging.error("could not parse: {0}".format(path),
                    exc_info=sys.exc_info())
            raise

        self.result_cache[path] = result

        self.stack.pop_stack()

        return result

    def __call__(self, s, l, t):
        try:
            return self.call_include(t[0])
        except:
            log.error("error during include", exc_info=sys.exc_info())
            raise

    def mark(self, s, l, t):
        last_path = self.stack.peek_stack()
        state = IncludeState(last_path, self.root, self.fake_dir)
        return tuple([state] + list(t))


__all__ = [
    "IncludeStack",
    "IncludeHandler"
]
