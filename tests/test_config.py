from keystone import config
from keystone import exception
from keystone import test


CONF = config.CONF


class ConfigTestCase(test.TestCase):
    def test_paste_config(self):
        self.assertEqual(config.find_paste_config(),
                         test.etcdir('keystone-paste.ini'))
        self.opt_in_group('paste_deploy', config_file='XYZ')
        self.assertRaises(exception.PasteConfigNotFound,
                          config.find_paste_config)
        self.opt_in_group('paste_deploy', config_file='')
        self.assertEqual(config.find_paste_config(),
                         test.etcdir('keystone.conf.sample'))
