import unittest

import tests.basicswap.test_other as test_other
import tests.basicswap.test_prepare as test_prepare
import tests.basicswap.test_run as test_run


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_other)
    suite.addTests(loader.loadTestsFromModule(test_prepare))
    suite.addTests(loader.loadTestsFromModule(test_run))

    return suite
