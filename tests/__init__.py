import unittest

import tests.test_run
import tests.test_other


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(tests.test_run)
    suite.addTests(loader.loadTestsFromModule(tests.test_other))
    return suite
