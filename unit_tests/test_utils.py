import unittest


class CharmTestCase(unittest.TestCase):

    def _patch(self, method):
        _m = unittest.mock.patch.object(self.obj, method)
        mock = _m.start()
        self.addCleanup(_m.stop)
        return mock

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self._patch(method))
