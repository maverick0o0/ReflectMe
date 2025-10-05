import sys
import types
import unittest

# Stub burp interfaces
burp_module = types.ModuleType('burp')

class _IBurpExtender(object):
    pass

class _ITab(object):
    pass

class _IHttpListener(object):
    pass

class _ScanIssue(object):
    pass

class _Parameter(object):
    PARAM_URL = 0

class _IHttpService(object):
    pass

burp_module.IBurpExtender = _IBurpExtender
burp_module.ITab = _ITab
burp_module.IHttpListener = _IHttpListener
burp_module.IScanIssue = _ScanIssue
burp_module.IParameter = _Parameter
burp_module.IHttpService = _IHttpService
sys.modules.setdefault('burp', burp_module)

# Stub Java Swing/AWT dependencies
java_module = types.ModuleType('java')
awt_module = types.ModuleType('java.awt')

class Dimension(object):
    def __init__(self, *args, **kwargs):
        pass

awt_module.Dimension = Dimension
sys.modules.setdefault('java', java_module)
sys.modules.setdefault('java.awt', awt_module)
java_module.awt = awt_module

awt_event_module = types.ModuleType('java.awt.event')
class ActionListener(object):
    pass
awt_event_module.ActionListener = ActionListener
sys.modules.setdefault('java.awt.event', awt_event_module)

java_util_module = types.ModuleType('java.util')
class ArrayList(list):
    def add(self, value):
        self.append(value)
java_util_module.ArrayList = ArrayList
sys.modules.setdefault('java.util', java_util_module)
java_module.util = java_util_module

swing_module = types.ModuleType('javax.swing')
class _SwingComponent(object):
    def __init__(self, *args, **kwargs):
        pass

for name in [
    'JPanel', 'JLabel', 'JCheckBox', 'JButton', 'JTextField',
    'JScrollPane', 'JTable', 'BoxLayout', 'JTextArea', 'JSpinner',
    'SpinnerNumberModel', 'KeyStroke', 'AbstractAction'
]:
    setattr(swing_module, name, type(name, (_SwingComponent,), {}))
sys.modules.setdefault('javax.swing', swing_module)

swing_table_module = types.ModuleType('javax.swing.table')
class AbstractTableModel(object):
    pass
swing_table_module.AbstractTableModel = AbstractTableModel
sys.modules.setdefault('javax.swing.table', swing_table_module)

swing_event_module = types.ModuleType('javax.swing.event')
class ChangeListener(object):
    pass
swing_event_module.ChangeListener = ChangeListener
sys.modules.setdefault('javax.swing.event', swing_event_module)

java_net_module = types.ModuleType('java.net')

class URL(object):
    def __init__(self, value):
        self._value = value

    def toString(self):
        return self._value

java_net_module.URL = URL
sys.modules.setdefault('java.net', java_net_module)
java_module.net = java_net_module

jarray_module = types.ModuleType('jarray')

def array(typecode, values):
    return list(values)

jarray_module.array = array
sys.modules.setdefault('jarray', jarray_module)

from reflectme import BurpExtender


class MockResponseInfo(object):
    def __init__(self, headers, body_offset, status_code=200):
        self._headers = headers
        self._body_offset = body_offset
        self._status_code = status_code

    def getStatusCode(self):
        return self._status_code

    def getBodyOffset(self):
        return self._body_offset

    def getHeaders(self):
        return self._headers


class MockByteArray(str):
    def __new__(cls, raw, response_info):
        obj = str.__new__(cls, raw)
        obj.response_info = response_info
        return obj

    def tostring(self):
        return str(self)


class MockHelpers(object):
    def analyzeResponse(self, response_bytes):
        return response_bytes.response_info

    def stringToBytes(self, value):
        return value

    def indexOf(self, data, pattern, case_sensitive, start, end):
        segment = data[start:end]
        idx = segment.find(pattern)
        if idx == -1:
            return -1
        return start + idx

    def urlEncode(self, value):
        return value


class MockCallbacks(object):
    def __init__(self):
        self.saved_messages = []

    def saveBuffersToTempFiles(self, http_request_response):
        self.saved_messages.append(http_request_response)
        return http_request_response


class MockHttpRequestResponse(object):
    def __init__(self, raw, response_info):
        self._raw = raw
        self._response_bytes = MockByteArray(raw, response_info)

    def getResponse(self):
        return self._response_bytes


def build_response(payload):
    headers = ["HTTP/1.1 200 OK", "Content-Type: text/html"]
    header_blob = "\r\n".join(headers) + "\r\n\r\n"
    body = "Hello {} world".format(payload)
    body_offset = len(header_blob)
    raw = header_blob + body
    response_info = MockResponseInfo(headers, body_offset)
    return MockHttpRequestResponse(raw, response_info)


class DummyAllowedModel(object):
    def get_enabled_values(self):
        return ['text/html']


class ReflectMeLiteralMatchTest(unittest.TestCase):
    def test_literal_payload_with_special_chars_detected(self):
        extender = BurpExtender.__new__(BurpExtender)
        extender._callbacks = MockCallbacks()
        extender._helpers = MockHelpers()
        extender._allowed_model = DummyAllowedModel()
        extender._debug_verbose = False
        extender._debug_max_dump = 4000

        payload = '<"mmdhacker">'
        response = build_response(payload)
        issue_entries = []
        message_markers = {}
        service = object()
        rate_key = ('localhost', 80, 'http')
        mode = 'append'
        template = 'custom'
        canary = 'mmdhacker'
        param_set = [{'name': 'q'}]

        result = extender._handle_test_response(response, payload, service, rate_key,
                                                mode, template, canary, param_set,
                                                issue_entries, message_markers)
        self.assertTrue(result)
        self.assertEqual(len(issue_entries), 1)
        marker_entry = list(message_markers.values())[0]
        start, end = marker_entry['markers'][0]
        reflected = response.getResponse().tostring()[start:end]
        self.assertEqual(reflected, payload)
        snippet = issue_entries[0]['snippet']
        self.assertIn('<"mmdhacker">', snippet)


if __name__ == '__main__':
    unittest.main()
