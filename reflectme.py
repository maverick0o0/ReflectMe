# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IHttpListener, IScanIssue, IParameter
from java.awt import Dimension
from java.awt.event import ActionListener
from java.util import ArrayList
from javax.swing import (JPanel, JLabel, JCheckBox, JButton, JTextField,
                         JScrollPane, JTable, BoxLayout, JTextArea, JSpinner,
                         SpinnerNumberModel, KeyStroke)
from javax.swing.table import AbstractTableModel
from javax.swing.event import ChangeListener
from javax.swing import AbstractAction
from jarray import array as jarray
import threading
import re
import json
import traceback

MAX_TESTS = 20


class AllowedContentTypeTableModel(AbstractTableModel):
    def __init__(self):
        self._columns = ["Enabled", "Content-type"]
        self._data = []
        self._index = {}

    def add_value(self, value, enabled=True):
        key = value.lower()
        if key in self._index:
            return False
        row = [bool(enabled), value]
        self._index[key] = len(self._data)
        self._data.append(row)
        self.fireTableDataChanged()
        return True

    def remove_indices(self, indices):
        if not indices:
            return
        indices = sorted(indices, reverse=True)
        for idx in indices:
            if 0 <= idx < len(self._data):
                key = self._data[idx][1].lower()
                if key in self._index:
                    del self._index[key]
                del self._data[idx]
        self._rebuild_index()
        self.fireTableDataChanged()

    def _rebuild_index(self):
        self._index = {}
        for i, row in enumerate(self._data):
            self._index[row[1].lower()] = i

    def get_enabled_values(self):
        values = []
        for enabled, value in self._data:
            if enabled:
                values.append(value)
        return values

    def getRowCount(self):
        return len(self._data)

    def getColumnCount(self):
        return len(self._columns)

    def getColumnName(self, columnIndex):
        return self._columns[columnIndex]

    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            from java.lang import Boolean
            return Boolean
        from java.lang import String
        return String

    def isCellEditable(self, rowIndex, columnIndex):
        return columnIndex == 0

    def getValueAt(self, rowIndex, columnIndex):
        return self._data[rowIndex][columnIndex]

    def setValueAt(self, value, rowIndex, columnIndex):
        if rowIndex < 0 or rowIndex >= len(self._data):
            return
        if columnIndex == 0:
            self._data[rowIndex][columnIndex] = bool(value)
            self.fireTableRowsUpdated(rowIndex, rowIndex)


class TopParamsTableModel(AbstractTableModel):
    def __init__(self):
        self._columns = ["Enabled", "Param name"]
        self._data = []
        self._index = {}

    def add_values(self, values, enabled=True):
        added = False
        for value in values:
            key = value.lower()
            if key in self._index:
                continue
            row = [bool(enabled), value]
            self._index[key] = len(self._data)
            self._data.append(row)
            added = True
        if added:
            self.fireTableDataChanged()
        return added

    def remove_indices(self, indices):
        if not indices:
            return
        indices = sorted(indices, reverse=True)
        for idx in indices:
            if 0 <= idx < len(self._data):
                key = self._data[idx][1].lower()
                if key in self._index:
                    del self._index[key]
                del self._data[idx]
        self._rebuild_index()
        self.fireTableDataChanged()

    def _rebuild_index(self):
        self._index = {}
        for i, row in enumerate(self._data):
            self._index[row[1].lower()] = i

    def get_enabled_values(self):
        values = []
        for enabled, value in self._data:
            if enabled:
                values.append(value)
        return values

    def getRowCount(self):
        return len(self._data)

    def getColumnCount(self):
        return len(self._columns)

    def getColumnName(self, columnIndex):
        return self._columns[columnIndex]

    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            from java.lang import Boolean
            return Boolean
        from java.lang import String
        return String

    def isCellEditable(self, rowIndex, columnIndex):
        return columnIndex == 0

    def getValueAt(self, rowIndex, columnIndex):
        return self._data[rowIndex][columnIndex]

    def setValueAt(self, value, rowIndex, columnIndex):
        if rowIndex < 0 or rowIndex >= len(self._data):
            return
        if columnIndex == 0:
            self._data[rowIndex][columnIndex] = bool(value)
            self.fireTableRowsUpdated(rowIndex, rowIndex)


class ReflectMeIssue(IScanIssue):
    def __init__(self, httpService, url, issueName, issueDetail, severity,
                 confidence, httpMessages):
        self._httpService = httpService
        self._url = url
        self._issueName = issueName
        self._issueDetail = issueDetail
        self._severity = severity
        self._confidence = confidence
        self._httpMessages = httpMessages

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


class ReflectMeActionListener(ActionListener):
    def __init__(self, callback):
        self._callback = callback

    def actionPerformed(self, event):
        try:
            self._callback(event)
        except Exception:
            traceback.print_exc()


class ReflectMeChangeListener(ChangeListener):
    def __init__(self, callback):
        self._callback = callback

    def stateChanged(self, event):
        try:
            self._callback(event)
        except Exception:
            traceback.print_exc()


class ReflectMeAbstractAction(AbstractAction):
    def __init__(self, callback):
        AbstractAction.__init__(self)
        self._callback = callback

    def actionPerformed(self, event):
        try:
            self._callback(event)
        except Exception:
            traceback.print_exc()


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("ReflectMe")
        self._lock = threading.RLock()
        self._running = False
        self._scope_only = True
        self._extract_from_resp = False
        self._check_individually = False
        self._chunk = 10
        self._scanned_urls = set()
        self._rate_limit_counts = {}
        self._rate_limit_blocked = set()
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def _build_ui(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.add(JLabel("Scanner options"))

        self._scope_checkbox = JCheckBox("Scope only (just check in-scope targets)", True)
        self._scope_checkbox.addActionListener(ReflectMeActionListener(self._toggle_scope))
        options_panel.add(self._scope_checkbox)

        self._extract_checkbox = JCheckBox("Extract params from response", False)
        self._extract_checkbox.addActionListener(ReflectMeActionListener(self._toggle_extract))
        options_panel.add(self._extract_checkbox)

        self._check_individual_checkbox = JCheckBox("Check parameters individually", False)
        self._check_individual_checkbox.addActionListener(ReflectMeActionListener(self._toggle_check_individual))
        options_panel.add(self._check_individual_checkbox)

        panel.add(options_panel)

        allowed_panel = JPanel()
        allowed_panel.setLayout(BoxLayout(allowed_panel, BoxLayout.Y_AXIS))
        allowed_panel.add(JLabel("Allowed Content-Type:"))

        add_row_panel = JPanel()
        add_row_panel.setLayout(BoxLayout(add_row_panel, BoxLayout.X_AXIS))
        self._content_type_field = JTextField()
        add_row_panel.add(self._content_type_field)
        add_button = JButton("Add")
        add_button.addActionListener(ReflectMeActionListener(self._add_content_type))
        add_row_panel.add(add_button)
        allowed_panel.add(add_row_panel)

        self._allowed_model = AllowedContentTypeTableModel()
        defaults = [
            "text/html",
            "application/xhtml+xml",
            "application/xml",
            "text/xml",
            "image/svg+xml",
            "text/xsl",
            "application/vnd.wap.xhtml+xml",
            "multipart/x-mixed-replace",
            "application/rdf+xml",
            "application/mathml+xml",
            "application/json",
            "text/plain",
        ]
        for value in defaults:
            self._allowed_model.add_value(value, True)

        self._allowed_table = JTable(self._allowed_model)
        column = self._allowed_table.getColumnModel().getColumn(0)
        column.setPreferredWidth(80)
        column.setMaxWidth(80)
        column.setMinWidth(60)
        allowed_scroll = JScrollPane(self._allowed_table)
        allowed_scroll.setPreferredSize(Dimension(0, 220))
        allowed_panel.add(allowed_scroll)

        delete_button = JButton("Delete")
        delete_button.addActionListener(ReflectMeActionListener(self._delete_content_types))
        allowed_panel.add(delete_button)

        panel.add(allowed_panel)

        top_params_panel = JPanel()
        top_params_panel.setLayout(BoxLayout(top_params_panel, BoxLayout.Y_AXIS))
        top_params_panel.add(JLabel("Top params:"))

        top_input_panel = JPanel()
        top_input_panel.setLayout(BoxLayout(top_input_panel, BoxLayout.X_AXIS))
        self._top_params_area = JTextArea(3, 20)
        top_scroll_area = JScrollPane(self._top_params_area)
        top_scroll_area.setPreferredSize(Dimension(0, 80))
        top_input_panel.add(top_scroll_area)
        top_add_button = JButton("Add")
        top_add_button.addActionListener(ReflectMeActionListener(self._add_top_params))
        top_input_panel.add(top_add_button)
        top_params_panel.add(top_input_panel)

        self._top_params_area.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "addTopParams")
        self._top_params_area.getActionMap().put("addTopParams", ReflectMeAbstractAction(self._add_top_params))

        self._top_params_model = TopParamsTableModel()
        self._top_params_table = JTable(self._top_params_model)
        top_column = self._top_params_table.getColumnModel().getColumn(0)
        top_column.setPreferredWidth(80)
        top_column.setMaxWidth(80)
        top_column.setMinWidth(60)
        top_scroll = JScrollPane(self._top_params_table)
        top_scroll.setPreferredSize(Dimension(0, 220))
        top_params_panel.add(top_scroll)

        top_delete_button = JButton("Delete")
        top_delete_button.addActionListener(ReflectMeActionListener(self._delete_top_params))
        top_params_panel.add(top_delete_button)

        panel.add(top_params_panel)

        chunk_panel = JPanel()
        chunk_panel.setLayout(BoxLayout(chunk_panel, BoxLayout.X_AXIS))
        chunk_panel.add(JLabel("Chunk (params per request):"))
        self._chunk_spinner = JSpinner(SpinnerNumberModel(10, 1, 50, 1))
        self._chunk_spinner.addChangeListener(ReflectMeChangeListener(self._chunk_changed))
        chunk_panel.add(self._chunk_spinner)
        panel.add(chunk_panel)

        control_panel = JPanel()
        control_panel.setLayout(BoxLayout(control_panel, BoxLayout.X_AXIS))

        self._start_button = JButton("Start")
        self._start_button.addActionListener(ReflectMeActionListener(self._start_scanner))
        control_panel.add(self._start_button)

        self._stop_button = JButton("Stop")
        self._stop_button.addActionListener(ReflectMeActionListener(self._stop_scanner))
        control_panel.add(self._stop_button)

        clear_button = JButton("Clear scanned URLs")
        clear_button.addActionListener(ReflectMeActionListener(self._clear_scanned))
        control_panel.add(clear_button)

        self._status_label = JLabel("Status: Stopped")
        control_panel.add(self._status_label)

        panel.add(control_panel)

        self._main_panel = panel

        self._content_type_field.addActionListener(ReflectMeActionListener(self._add_content_type))

    def getTabCaption(self):
        return "ReflectMe"

    def getUiComponent(self):
        return self._main_panel

    def _toggle_scope(self, event):
        self._scope_only = self._scope_checkbox.isSelected()

    def _toggle_extract(self, event):
        self._extract_from_resp = self._extract_checkbox.isSelected()

    def _toggle_check_individual(self, event):
        self._check_individually = self._check_individual_checkbox.isSelected()

    def _chunk_changed(self, event):
        try:
            value = int(self._chunk_spinner.getValue())
        except Exception:
            value = 10
        if value < 1 or value > 50:
            value = 10
            self._chunk_spinner.setValue(10)
        self._chunk = value

    def _start_scanner(self, event):
        with self._lock:
            self._running = True
            self._status_label.setText("Status: Running")

    def _stop_scanner(self, event):
        with self._lock:
            self._running = False
            self._status_label.setText("Status: Stopped")

    def _clear_scanned(self, event):
        with self._lock:
            self._scanned_urls.clear()
            self._rate_limit_counts.clear()
            self._rate_limit_blocked.clear()

    def _add_content_type(self, event):
        value = self._content_type_field.getText()
        if value is None:
            return
        value = value.strip()
        if not value:
            return
        self._allowed_model.add_value(value, True)
        self._content_type_field.setText("")

    def _delete_content_types(self, event):
        rows = self._allowed_table.getSelectedRows()
        if rows is None or len(rows) == 0:
            return
        indices = []
        for row in rows:
            try:
                model_index = self._allowed_table.convertRowIndexToModel(row)
            except Exception:
                model_index = row
            indices.append(model_index)
        self._allowed_model.remove_indices(indices)

    def _add_top_params(self, event):
        raw = self._top_params_area.getText()
        if raw is None:
            return
        raw = raw.strip()
        if not raw:
            return
        parts = re.split(r'[\s,;]+', raw)
        values = []
        for part in parts:
            part = part.strip()
            if part:
                values.append(part)
        if values:
            self._top_params_model.add_values(values, True)
        self._top_params_area.setText("")

    def _delete_top_params(self, event):
        rows = self._top_params_table.getSelectedRows()
        if rows is None or len(rows) == 0:
            return
        indices = []
        for row in rows:
            try:
                model_index = self._top_params_table.convertRowIndexToModel(row)
            except Exception:
                model_index = row
            indices.append(model_index)
        self._top_params_model.remove_indices(indices)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not self._running:
                return
            if messageIsRequest:
                return
            if toolFlag != self._callbacks.TOOL_PROXY:
                return
            request_bytes = messageInfo.getRequest()
            if request_bytes is None:
                return
            if self._has_loop_header(request_bytes):
                return
            response_bytes = messageInfo.getResponse()
            if response_bytes is None:
                return
            if self._has_loop_header(response_bytes):
                return
            request_info = self._helpers.analyzeRequest(messageInfo)
            if request_info is None:
                return
            url = request_info.getUrl()
            if url is None:
                return
            if self._scope_only and not self._callbacks.isInScope(url):
                return
            url_string = str(url.toString())
            with self._lock:
                if url_string in self._scanned_urls:
                    return
                self._scanned_urls.add(url_string)
            response_info = self._helpers.analyzeResponse(response_bytes)
            if response_info is None:
                return
            if not self._is_allowed_content_type(response_info):
                return
            self._execute_scanner(messageInfo, request_info, response_info, url_string)
        except Exception:
            traceback.print_exc()

    def _has_loop_header(self, message_bytes):
        try:
            info = self._helpers.analyzeRequest(message_bytes)
            headers = info.getHeaders()
        except Exception:
            try:
                info = self._helpers.analyzeResponse(message_bytes)
                headers = info.getHeaders()
            except Exception:
                headers = None
        if headers is None:
            return False
        for header in headers:
            if header is None:
                continue
            try:
                lower = header.lower()
            except Exception:
                continue
            if lower.startswith("x-jxr-ext"):
                return True
        return False

    def _is_allowed_content_type(self, response_info):
        try:
            headers = response_info.getHeaders()
            if headers is None:
                return False
            allowed = self._allowed_model.get_enabled_values()
            if not allowed:
                return False
            content_type = None
            for header in headers:
                if header is None:
                    continue
                lower = header.lower()
                if lower.startswith("content-type"):
                    parts = header.split(":", 1)
                    if len(parts) == 2:
                        content_type = parts[1].strip()
                    break
            if content_type is None:
                return False
            lowered = content_type.lower()
            for value in allowed:
                if value.lower() in lowered:
                    return True
            return False
        except Exception:
            traceback.print_exc()
            return False

    def _execute_scanner(self, messageInfo, request_info, response_info, url_key):
        try:
            service = messageInfo.getHttpService()
            rate_key = self._rate_limit_key(service)
            with self._lock:
                if rate_key in self._rate_limit_blocked:
                    return
            parameters = request_info.getParameters()
            existing_params = []
            for param in parameters:
                try:
                    param_type = param.getType()
                except Exception:
                    continue
                if param_type == IParameter.PARAM_URL:
                    name = param.getName()
                    value = param.getValue()
                    if name is None:
                        continue
                    existing_params.append({
                        'name': name,
                        'base_value': value if value is not None else '',
                        'is_existing': True,
                        'source': 'query'
                    })
            has_query = len(existing_params) > 0
            top_params_enabled = self._top_params_model.get_enabled_values()
            target_params = list(existing_params)
            if top_params_enabled:
                for name in top_params_enabled:
                    target_params.append({
                        'name': name,
                        'base_value': '',
                        'is_existing': False,
                        'source': 'top'
                    })
            response_bytes = messageInfo.getResponse()
            response_raw = self._to_bytes(response_bytes)
            body_offset = response_info.getBodyOffset()
            body_bytes = response_raw[body_offset:]
            content_type = self._extract_content_type(response_info)
            extracted_params = []
            if (not has_query) and self._extract_from_resp:
                extracted_params = self.extract_parameters_from_html_or_js_or_json_or_xml(body_bytes, content_type)
                for name in extracted_params:
                    target_params.append({
                        'name': name,
                        'base_value': '',
                        'is_existing': False,
                        'source': 'extracted'
                    })
            if not has_query and not extracted_params:
                return
            if not target_params:
                return
            base_headers = list(request_info.getHeaders())
            request_raw = self._to_bytes(messageInfo.getRequest())
            request_body = request_raw[request_info.getBodyOffset():]
            first_line = base_headers[0] if base_headers else ''
            parts = first_line.split(' ', 2)
            if len(parts) < 3:
                method = request_info.getMethod()
                http_version = 'HTTP/1.1'
            else:
                method = parts[0]
                http_version = parts[2]
            path = request_info.getUrl().getPath()
            if not path:
                path = '/'
            base_query_pairs = []
            for param in existing_params:
                base_query_pairs.append([param['name'], param['base_value']])
            chunks = self._chunk_list(target_params, self._chunk)
            append_templates = [
                '<u>{CANARY}</u>',
                '<{CANARY}>',
                '<{CANARY}',
                '"{CANARY}',
                "'{CANARY}",
                '`{CANARY}'
            ]
            replace_templates = [
                '<u>{CANARY}</u>',
                '<{CANARY}>',
                '<{CANARY}',
                '"{CANARY}',
                '`{CANARY}'
            ]
            tests_sent = 0
            issue_entries = []
            message_markers = {}
            for mode in ['append', 'replace']:
                templates = append_templates if mode == 'append' else replace_templates
                if mode == 'replace' and not target_params:
                    continue
                for chunk in chunks:
                    if not chunk:
                        continue
                    param_sets = []
                    if self._check_individually:
                        for param in chunk:
                            param_sets.append([param])
                    else:
                        param_sets.append(list(chunk))
                    for param_set in param_sets:
                        for template in templates:
                            if tests_sent >= MAX_TESTS:
                                break
                            canary = 'mmdhacker'
                            payload = template.replace('{CANARY}', canary)
                            mutated_query = self._build_query_for_request(mode, param_set, base_query_pairs, payload, canary)
                            if mutated_query is None:
                                continue
                            new_headers = self._prepare_headers(base_headers, method, path, mutated_query, http_version)
                            request_bytes = self._helpers.buildHttpMessage(new_headers, request_body)
                            try:
                                http_request_response = self._callbacks.makeHttpRequest(service, request_bytes)
                            except Exception:
                                continue
                            tests_sent += 1
                            if http_request_response is None:
                                continue
                            self._handle_test_response(http_request_response, payload, service, rate_key,
                                                       mode, template, canary, param_set,
                                                       issue_entries, message_markers)
                            with self._lock:
                                if rate_key in self._rate_limit_blocked:
                                    return
                        if tests_sent >= MAX_TESTS:
                            break
                    if tests_sent >= MAX_TESTS:
                        break
                if tests_sent >= MAX_TESTS:
                    break
            if issue_entries:
                http_messages = []
                for key in message_markers:
                    item = message_markers[key]
                    markers_list = ArrayList()
                    for start, end in item['markers']:
                        markers_list.add(jarray('i', [int(start), int(end)]))
                    base_msg = item['message']
                    try:
                        marked = self._callbacks.applyMarkers(base_msg, None, markers_list)
                        http_messages.append(marked if marked is not None else base_msg)
                    except Exception:
                        http_messages.append(base_msg)
                detail = self._build_issue_detail(issue_entries)
                issue = ReflectMeIssue(service, request_info.getUrl(),
                                       "Reflected input detected (ReflectMe)",
                                       detail, "Information", "Firm", http_messages)
                self._callbacks.addScanIssue(issue)
        except Exception:
            traceback.print_exc()

    def _rate_limit_key(self, service):
        try:
            host = service.getHost()
        except Exception:
            host = ''
        try:
            port = service.getPort()
        except Exception:
            port = 0
        try:
            protocol = service.getProtocol()
        except Exception:
            protocol = ''
        return (host, port, protocol)

    def _build_query_for_request(self, mode, param_set, base_query_pairs, payload, canary):
        try:
            append_mode = mode == 'append'
            if append_mode:
                new_params = []
                for name, value in base_query_pairs:
                    new_params.append([name, value])
            else:
                new_params = []
            for param in param_set:
                name = param['name']
                base_value = param.get('base_value', '')
                if base_value is None:
                    base_value = ''
                if append_mode:
                    mutated_value = base_value + payload
                    if not param.get('is_existing') and not base_value:
                        mutated_value = payload
                else:
                    mutated_value = payload
                updated = False
                if append_mode and param.get('is_existing'):
                    for pair in new_params:
                        if pair[0] == name:
                            pair[1] = mutated_value
                            updated = True
                            break
                if not updated:
                    new_params.append([name, mutated_value])
            query_parts = []
            for name, value in new_params:
                if name is None:
                    continue
                encoded_name = self._helpers.urlEncode(name)
                encoded_value = self._helpers.urlEncode(value if value is not None else '')
                query_parts.append(encoded_name + "=" + encoded_value)
            return '&'.join(query_parts)
        except Exception:
            traceback.print_exc()
            return None

    def _prepare_headers(self, base_headers, method, path, query, http_version):
        headers = []
        first_line = None
        for header in base_headers:
            if header is None:
                continue
            lower = header.lower()
            if lower.startswith('x-jxr-ext'):
                continue
            if first_line is None:
                first_line = header
            else:
                headers.append(header)
        if method is None and first_line:
            parts = first_line.split(' ', 2)
            if parts:
                method = parts[0]
            if len(parts) == 3:
                http_version = parts[2]
        if method is None:
            method = 'GET'
        if http_version is None:
            http_version = 'HTTP/1.1'
        if not path:
            path = '/'
        if query:
            request_path = path + '?' + query
        else:
            request_path = path
        start_line = method + ' ' + request_path + ' ' + http_version
        headers.insert(0, start_line)
        headers.append('X-JXR-EXT: 1')
        return headers

    def _handle_test_response(self, http_request_response, payload, service, rate_key,
                              mode, template, canary, param_set, issue_entries,
                              message_markers):
        try:
            response_bytes = http_request_response.getResponse()
            if response_bytes is None:
                return False
            response_info = self._helpers.analyzeResponse(response_bytes)
            if response_info is None:
                return False
            status_code = response_info.getStatusCode()
            if status_code == 429:
                self._register_rate_limit(service, rate_key, http_request_response)
            if not self._is_allowed_content_type(response_info):
                return False
            response_raw = self._to_bytes(response_bytes)
            body_offset = response_info.getBodyOffset()
            body_bytes = response_raw[body_offset:]
            if payload is None:
                return False
            payload_bytes = self._to_bytes(payload)
            if payload_bytes is None:
                return False
            if payload_bytes == '':
                return False
            index = body_bytes.find(payload_bytes)
            if index == -1:
                return False
            markers = []
            payload_length = len(payload_bytes)
            while index != -1:
                start = body_offset + index
                end = start + payload_length
                markers.append([start, end])
                index = body_bytes.find(payload_bytes, index + payload_length)
            if not markers:
                return False
            base_msg = http_request_response
            key = id(base_msg)
            if key not in message_markers:
                message_markers[key] = {'message': base_msg, 'markers': []}
            for marker in markers:
                message_markers[key]['markers'].append(marker)
            content_type = self._extract_content_type(response_info)
            snippet = self._build_snippet(body_bytes, payload_bytes)
            try:
                basestring
            except NameError:
                string_types = (str,)
            else:
                string_types = (basestring,)
            if isinstance(payload, string_types):
                payload_literal = payload
            else:
                payload_literal = self._safe_to_unicode(payload_bytes)
            params_names = []
            for param in param_set:
                params_names.append(param['name'])
            entry = {
                'parameter': ', '.join(params_names),
                'mode': mode,
                'strategy': 'least-change' if mode == 'append' else 'full-replace',
                'payload': payload_literal,
                'content_type': content_type,
                'snippet': snippet
            }
            issue_entries.append(entry)
            return True
        except Exception:
            traceback.print_exc()
            return False

    def _register_rate_limit(self, service, rate_key, http_request_response):
        try:
            analyze = self._helpers.analyzeRequest(http_request_response)
            url = analyze.getUrl() if analyze is not None else None
            url_string = str(url.toString()) if url is not None else ''
        except Exception:
            url_string = ''
        with self._lock:
            entry = self._rate_limit_counts.get(rate_key)
            if entry is None:
                entry = {'count': 0, 'urls': [], 'issued': False}
                self._rate_limit_counts[rate_key] = entry
            entry['count'] += 1
            if len(entry['urls']) < 5 and url_string:
                entry['urls'].append(url_string)
            if entry['count'] > 5 and not entry['issued']:
                entry['issued'] = True
                self._rate_limit_blocked.add(rate_key)
                detail = self._build_rate_limit_detail(entry)
                messages = [self._callbacks.saveBuffersToTempFiles(http_request_response)]
                issue = ReflectMeIssue(service, url,
                                       "ReflectMe: received >5 responses with HTTP 429 (Too Many Requests) — testing suspended for this target/timeframe.",
                                       detail, "Information", "Firm", messages)
                self._callbacks.addScanIssue(issue)

    def _build_rate_limit_detail(self, entry):
        count = entry.get('count', 0)
        urls = entry.get('urls', [])
        detail = [
            "<p>ReflectMe observed {0} responses with HTTP 429 (Too Many Requests).</p>".format(count)
        ]
        if urls:
            detail.append("<p>Sample URLs:</p><ul>")
            for url in urls:
                detail.append("<li>{0}</li>".format(self._html_escape(url)))
            detail.append("</ul>")
        return ''.join(detail)

    def _build_issue_detail(self, entries):
        parts = [
            '<table border="1" cellpadding="4" cellspacing="0">',
            '<tr><th>Parameter</th><th>Mode</th><th>Strategy</th><th>Payload</th><th>Reflected?</th><th>Content-Type</th><th>Context snippet</th></tr>'
        ]
        for entry in entries:
            parts.append('<tr>')
            parts.append('<td>{0}</td>'.format(self._html_escape(entry.get('parameter', ''))))
            parts.append('<td>{0}</td>'.format(self._html_escape(entry.get('mode', ''))))
            parts.append('<td>{0}</td>'.format(self._html_escape(entry.get('strategy', ''))))
            payload = entry.get('payload', '')
            parts.append('<td><code>{0}</code></td>'.format(self._html_escape(payload)))
            parts.append('<td>yes</td>')
            parts.append('<td>{0}</td>'.format(self._html_escape(entry.get('content_type', ''))))
            parts.append('<td>{0}</td>'.format(self._html_escape(entry.get('snippet', ''))))
            parts.append('</tr>')
        parts.append('</table>')
        return ''.join(parts)

    def _build_snippet(self, body_bytes, payload_bytes):
        try:
            if payload_bytes is None:
                return ''
            if payload_bytes == '':
                return ''
            index = body_bytes.find(payload_bytes)
            if index == -1:
                return ''
            start = max(0, index - 50)
            end = min(len(body_bytes), index + len(payload_bytes) + 50)
            snippet_bytes = body_bytes[start:end]
            return self._safe_to_unicode(snippet_bytes)
        except Exception:
            traceback.print_exc()
            return ''

    def _chunk_list(self, data, size):
        chunks = []
        if size <= 0:
            size = 1
        for i in range(0, len(data), size):
            chunks.append(data[i:i + size])
        return chunks

    def _to_bytes(self, data):
        if data is None:
            return ''
        try:
            return data.tostring()
        except Exception:
            pass
        try:
            return ''.join(chr((b + 256) % 256) for b in data)
        except Exception:
            try:
                return str(data)
            except Exception:
                return ''

    def _extract_content_type(self, response_info):
        try:
            headers = response_info.getHeaders()
            if headers is None:
                return ''
            for header in headers:
                if header is None:
                    continue
                lower = header.lower()
                if lower.startswith('content-type'):
                    parts = header.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
            return ''
        except Exception:
            traceback.print_exc()
            return ''

    def _html_escape(self, value):
        if value is None:
            return ''
        return value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _safe_to_unicode(self, data):
        if data is None:
            return ''
        try:
            if isinstance(data, unicode):
                return data
        except NameError:
            if isinstance(data, str):
                return data
        try:
            return data.decode('utf-8', 'replace')
        except Exception:
            try:
                return str(data)
            except Exception:
                return ''

    def extract_parameters_from_html_or_js_or_json_or_xml(self, body_bytes, content_type):
        results = []
        seen = set()

        def add_value(value):
            if value is None:
                return
            value = value.strip()
            if not value:
                return
            key = value.lower()
            if key in seen:
                return
            seen.add(key)
            results.append(value)

        text = self._safe_to_unicode(body_bytes)
        lower_ct = (content_type or '').lower()

        if 'json' in lower_ct:
            try:
                parsed = json.loads(text)

                def traverse(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.iteritems():
                            add_value(str(k))
                            traverse(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            traverse(item)
                traverse(parsed)
            except Exception:
                pass

        if 'xml' in lower_ct:
            try:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(text.encode('utf-8'))
                except Exception:
                    root = ET.fromstring(text)

                def walk(node):
                    for key, value in node.attrib.iteritems():
                        add_value(key)
                        add_value(value)
                    for child in list(node):
                        walk(child)
                walk(root)
            except Exception:
                pass

        try:
            name_matches = re.findall(r"<(?:input|textarea|select|button)[^>]*?(?:name|id)\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
            for match in name_matches:
                add_value(match)
        except Exception:
            pass

        try:
            var_matches = re.findall(r"\b(?:var|let|const)\s+([A-Za-z_][A-Za-z0-9_]*)", text)
            for match in var_matches:
                add_value(match)
        except Exception:
            pass

        try:
            object_key_matches = re.findall(r"['\"]([A-Za-z0-9_\-]+)['\"]\s*:", text)
            for match in object_key_matches:
                add_value(match)
        except Exception:
            pass

        try:
            data_layer_matches = re.findall(r"dataLayer\.push\s*\(\s*\{([^\}]*)\}", text)
            for segment in data_layer_matches:
                inner_keys = re.findall(r"['\"]([A-Za-z0-9_\-]+)['\"]\s*:", segment)
                for key in inner_keys:
                    add_value(key)
        except Exception:
            pass

        return results
