def arg(name, **kwargs):
    """Decorate the command class with an argparse argument"""
    def _decorator(cls):
        if not hasattr(cls, '_args'):
            setattr(cls, '_args', {})
        args = getattr(cls, '_args')
        args[name] = kwargs
        return cls
    return _decorator


class BaseCommand(object):
    """Provides a common pattern for keystone-manage commands"""
    # initialize to an empty dict, in case a command is not decorated
    _args = {}

    @staticmethod
    def append_parser(parser):
        """Appends this command's arguments to an argparser

        :param parser: argparse.ArgumentParser
        """
        args = BaseCommand._args
        for name in args.keys():
            parser.add_argument(name, **args[name])

    @staticmethod
    def run(args):
        """Handles argparse args and prints command results to stdout

        :param args: argparse Namespace
        """
        raise NotImplemented()
