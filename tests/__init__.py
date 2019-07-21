import unittest

import tests.test_other
import tests.test_prepare
import tests.test_run


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(tests.test_other)
    suite.addTests(loader.loadTestsFromModule(tests.test_prepare))
    suite.addTests(loader.loadTestsFromModule(tests.test_run))

    return suite
