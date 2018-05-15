import mock
import unittest


class CharmTestCase(unittest.TestCase):

    def setUp(self):
        self._patches = {}
        self._patches_start = {}

    def tearDown(self):
        for k, v in self._patches.items():
            v.stop()
            setattr(self, k, None)
        self._patches = None
        self._patches_start = None

    def _patch(self, method):
        _m = unittest.mock.patch.object(self.obj, method)
        mock = _m.start()
        self.addCleanup(_m.stop)
        return mock

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self._patch(method))

    def patch_object(self, obj, attr, return_value=None, name=None, new=None,
                     **kwargs):
        if name is None:
            name = attr
        if new is not None:
            mocked = mock.patch.object(obj, attr, new=new, **kwargs)
        else:
            mocked = mock.patch.object(obj, attr, **kwargs)
        self._patches[name] = mocked
        started = mocked.start()
        if new is None:
            started.return_value = return_value
        self._patches_start[name] = started
        setattr(self, name, started)

    def patch(self, item, return_value=None, name=None, new=None, **kwargs):
        if name is None:
            raise RuntimeError("Must pass 'name' to .patch()")
        if new is not None:
            mocked = mock.patch(item, new=new, **kwargs)
        else:
            mocked = mock.patch(item, **kwargs)
        self._patches[name] = mocked
        started = mocked.start()
        if new is None:
            started.return_value = return_value
        self._patches_start[name] = started
