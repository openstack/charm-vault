from unittest import mock
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


class TestConfig(object):

    def __init__(self):
        self.config = {}
        self.config_prev = {}

    def __call__(self, key=None):
        if key:
            return self.get(key)
        else:
            return self

    def previous(self, k):
        return self.config_prev[k] if k in self.config_prev else self.config[k]

    def set_previous(self, k, v):
        self.config_prev[k] = v

    def unset_previous(self, k):
        if k in self.config_prev:
            self.config_prev.pop(k)

    def changed(self, k):
        if not self.config_prev:
            return True
        return self.get(k) != self.previous(k)

    def get(self, attr=None):
        if not attr:
            return self
        try:
            return self.config[attr]
        except KeyError:
            return None

    def get_all(self):
        return self.config

    def set(self, attr, value):
        self.config[attr] = value

    def __getitem__(self, k):
        return self.get(k)


DUMMY_CERTIFICATE_SANITIZED = """-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUBTucjQO1X2maobZzRGoyrIclCikwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDcxNjA2MjQzOVoXDTI0MDcy
MzA2MjQzOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEApof+89fH3hsPxfKrQqyKZq3FN6XaJvQ6knCnPBmh+g5Q
JddawhnNj3RF/WZZs6xAEunahqp6vZtAlMe+9EiAKNMOpD3bzWRjn+AcVTnP1ey8
Z5e9JDD3Iqls/f+ZjiY8afVefLv1H74NRUYH4f2dKDJvAUxsI7dQ3l+2hRewLUh3
nSGpUx8hZ4vfWczf+ad31ADoFVH5lA74gn2pR5IzVo8vzV4kgNuf7j4FhJDE38i8
Yqg8rSvWUvJ8qMPrgw690m/HsrvINWegyDGZcEmV+FKXQ1ywu7FEPjdDVdvqiRbm
ZVyUUezGGmL6vHVj0IxoaBxH4oF3BkhCII0WNVCh1wIDAQABo1MwUTAdBgNVHQ4E
FgQUEpuYqSDsDOcbnz+84s3PD3/hDT0wHwYDVR0jBBgwFoAUEpuYqSDsDOcbnz+8
4s3PD3/hDT0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWo7d
j8ImS7DTLpQ+AcHbKB+mCr+PR6vc8im2hxmr4JgFQmEPnFEZw7J69IgtQX5Gii2D
ZkVAJdu/vwBcoOqNA9V4FT0H+waf/r/rVWJM5stGGl861xv7Z0qtwbma2Q5YWRVi
mmgDqZ7LkxpQADvXASdtxqdz9iHQqk0rEIpAkHIJ9GHiiTeZyw5xvQSFuCTkKnUE
fryz3NWEjQ+nmMCa/Ced01JpMAl97G8KoUyNLP6JuLMa6Aw3xj1Rzm3xwq1EXw3F
4yrorpLte/RtqB0QK2e8d+QxtE42RaGwxcx4I0cU0eANBf/mtSQ2ugjj0b1BWRi2
rJdsjaJKlkavdpVxUQ==
-----END CERTIFICATE-----
"""

DUMMY_CERTIFICATE_UNSANITIZED = '-----BEGIN CERTIFICATE-----\r\nMIIDCTCCAfGgAwIBAgIUBTucjQO1X2maobZzRGoyrIclCikwDQYJKoZIhvcNAQEL\rBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0MDcxNjA2MjQzOVoXDTI0MDcy\rMzA2MjQzOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\r\nAAOCAQ8AMIIBCgKCAQEApof+89fH3hsPxfKrQqyKZq3FN6XaJvQ6knCnPBmh+g5Q\r\nJddawhnNj3RF/WZZs6xAEunahqp6vZtAlMe+9EiAKNMOpD3bzWRjn+AcVTnP1ey8\r\nZ5e9JDD3Iqls/f+ZjiY8afVefLv1H74NRUYH4f2dKDJvAUxsI7dQ3l+2hRewLUh3\r\nnSGpUx8hZ4vfWczf+ad31ADoFVH5lA74gn2pR5IzVo8vzV4kgNuf7j4FhJDE38i8\r\nYqg8rSvWUvJ8qMPrgw690m/HsrvINWegyDGZcEmV+FKXQ1ywu7FEPjdDVdvqiRbm\r\nZVyUUezGGmL6vHVj0IxoaBxH4oF3BkhCII0WNVCh1wIDAQABo1MwUTAdBgNVHQ4E\r\nFgQUEpuYqSDsDOcbnz+84s3PD3/hDT0wHwYDVR0jBBgwFoAUEpuYqSDsDOcbnz+8\r\n4s3PD3/hDT0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAWo7d\r\nj8ImS7DTLpQ+AcHbKB+mCr+PR6vc8im2hxmr4JgFQmEPnFEZw7J69IgtQX5Gii2D\r\nZkVAJdu/vwBcoOqNA9V4FT0H+waf/r/rVWJM5stGGl861xv7Z0qtwbma2Q5YWRVi\r\nmmgDqZ7LkxpQADvXASdtxqdz9iHQqk0rEIpAkHIJ9GHiiTeZyw5xvQSFuCTkKnUE\r\nfryz3NWEjQ+nmMCa/Ced01JpMAl97G8KoUyNLP6JuLMa6Aw3xj1Rzm3xwq1EXw3F\r\n4yrorpLte/RtqB0QK2e8d+QxtE42RaGwxcx4I0cU0eANBf/mtSQ2ugjj0b1BWRi2\r\nrJdsjaJKlkavdpVxUQ==\r\n-----END CERTIFICATE-----\n'  # noqa: E501
