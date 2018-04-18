# unit tests

import mock
import sys

sys.path.append('src')
sys.path.append('src/lib')

global snap
snap = mock.MagicMock()
sys.modules['charms.layer'] = snap
