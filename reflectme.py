# -*- coding: utf-8 -*-
from burp import (IBurpExtender, ITab, IHttpListener, IScanIssue, IParameter,
                  IHttpService)
from java.awt import (Dimension, BorderLayout, GridBagLayout,
                      GridBagConstraints, Insets, FlowLayout, Color)
from java.awt.event import ActionListener
from java.util import ArrayList
from javax.swing import (JPanel, JLabel, JCheckBox, JButton, JTextField,
                         JScrollPane, JTable, BoxLayout, JTextArea, JSpinner,
                         SpinnerNumberModel, KeyStroke, JTabbedPane,
                         JSeparator, BorderFactory, UIManager, Box)
from javax.swing.table import AbstractTableModel
from javax.swing.event import ChangeListener
from javax.swing import AbstractAction
from jarray import array as jarray
from java.net import URL
import threading
import re
import json
import traceback
import zlib

TEMPLATES = [
    "<u>{CANARY}</u>",
    "<{CANARY}>",
    "<{CANARY}",
    '"{CANARY}',
    "'{CANARY}",
    "`{CANARY}"
]


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


class ReflectMeHttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("ReflectMe")
        self._lock = threading.RLock()
        self._running = False
        self._scope_only = True
        self._extract_from_resp = False
        self._use_top_params = False
        self._auto_check_urls_without_param = True
        self._check_individually = False
        self._chunk = 10
        self._max_tests = 20
        self._scanned_urls = set()
        self._rate_limit_counts = {}
        self._rate_limit_blocked = set()
        self._debug_verbose = True
        self._debug_max_dump = 4000
        self._emitted_first_reflect_issue = False
        self._last_seen_url = None
        self._last_seen_service = None
        self._custom_canary = ''
        self._build_ui()
        self._custom_canary = self._get_canary()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

    def _log(self, msg):
        if not getattr(self, '_debug_verbose', False):
            return
        try:
            text = self._safe_to_unicode('' if msg is None else msg)
        except Exception:
            try:
                text = str(msg)
            except Exception:
                text = ''
        # Ensure Output tab visibility
        try:
            self._callbacks.printOutput(text)
        except Exception:
            pass
        # Fallback to stdout
        try:
            print(text)
        except Exception:
            pass

    def _norm_severity(self, s):
        try:
            s = (s or '').strip().lower()
        except Exception:
            return "Information"
        if s == 'high':
            return 'High'
        if s in ('medium', 'med'):
            return 'Medium'
        if s == 'low':
            return 'Low'
        if s in ('information', 'info', 'informational'):
            return 'Information'
        return 'Information'

    def _norm_confidence(self, c):
        try:
            c = (c or '').strip().lower()
        except Exception:
            return 'Firm'
        if c in ('certain', 'sure'):
            return 'Certain'
        if c in ('firm', 'confident'):
            return 'Firm'
        if c in ('tentative', 'possible'):
            return 'Tentative'
        return 'Firm'

    def _persist_and_mark(self, base_msg, markers):
        try:
            persisted = self._callbacks.saveBuffersToTempFiles(base_msg)
        except Exception:
            persisted = base_msg
        markers_list = ArrayList()
        try:
            for start, end in (markers or []):
                markers_list.add(jarray('i', [int(start), int(end)]))
        except Exception:
            pass
        try:
            marked = self._callbacks.applyMarkers(persisted, None, markers_list)
            out_msg = marked if marked is not None else persisted
        except Exception:
            out_msg = persisted
        # Try to ensure visibility in the UI
        try:
            self._callbacks.addToSiteMap(out_msg)
        except Exception:
            pass
        return out_msg

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())

        tabs = JTabbedPane()
        tabs.addTab("Scan", self._makeScanTab())
        tabs.addTab("Content Types", self._makeContentTypesTab())
        tabs.addTab("Top Params", self._makeTopParamsTab())

        self._main_panel.add(tabs, BorderLayout.CENTER)
        self._main_panel.add(self._buildStatusBar(), BorderLayout.SOUTH)

        self._updateControlStates()
        self._updateStatusColor()

    def _makeScanTab(self):
        panel = JPanel(BorderLayout())
        panel.add(self._buildHeaderPanel(), BorderLayout.NORTH)

        content = JPanel()
        content.setLayout(BoxLayout(content, BoxLayout.Y_AXIS))
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        content.add(self._titled(self._buildScannerOptionsSection(), "Scanner options"))
        content.add(Box.createVerticalStrut(10))
        content.add(self._titled(self._buildPayloadLimitsSection(), "Payload & Limits"))
        content.add(Box.createVerticalStrut(10))
        content.add(self._titled(self._buildControlsSection(), "Controls"))

        panel.add(content, BorderLayout.CENTER)
        return panel

    def _makeContentTypesTab(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        action_bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        label = JLabel("Allowed Content-Type:")
        action_bar.add(label)

        self._content_type_field = JTextField()
        self._content_type_field.setColumns(24)
        self._content_type_field.setToolTipText("Add a MIME type to allow scanning responses.")
        label.setLabelFor(self._content_type_field)
        action_bar.add(self._content_type_field)

        add_button = JButton("Add")
        add_button.setMnemonic(ord('A'))
        add_button.setToolTipText("Add the specified content type.")
        add_button.addActionListener(ReflectMeActionListener(self._add_content_type))
        action_bar.add(add_button)

        self._content_type_field.addActionListener(ReflectMeActionListener(self._add_content_type))

        panel.add(action_bar, BorderLayout.NORTH)

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
            "text/plain",
        ]
        for value in defaults:
            self._allowed_model.add_value(value, True)

        self._allowed_table = JTable(self._allowed_model)
        self._allowed_table.setToolTipText("Toggle to enable or disable a content type for reflection checks.")
        self._installTableDefaults(self._allowed_table)
        column = self._allowed_table.getColumnModel().getColumn(0)
        column.setPreferredWidth(80)
        column.setMaxWidth(80)
        column.setMinWidth(60)

        allowed_scroll = JScrollPane(self._allowed_table)
        allowed_scroll.setPreferredSize(Dimension(0, 220))
        panel.add(allowed_scroll, BorderLayout.CENTER)

        delete_bar = self._buildButtonBar()
        delete_button = JButton("Delete")
        delete_button.setMnemonic(ord('D'))
        delete_button.setToolTipText("Remove selected content types.")
        delete_button.addActionListener(ReflectMeActionListener(self._delete_content_types))
        delete_bar.add(delete_button)
        panel.add(delete_bar, BorderLayout.SOUTH)

        return panel

    def _makeTopParamsTab(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        action_panel = JPanel(GridBagLayout())
        action_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0))

        self._top_params_area = JTextArea(3, 20)
        self._top_params_area.setLineWrap(True)
        self._top_params_area.setWrapStyleWord(True)
        self._top_params_area.setToolTipText("Enter parameters separated by spaces, commas, or semicolons. Press Enter to add.")
        top_scroll_area = JScrollPane(self._top_params_area)
        top_scroll_area.setPreferredSize(Dimension(0, 90))

        input_constraints = GridBagConstraints()
        input_constraints.gridx = 0
        input_constraints.gridy = 0
        input_constraints.weightx = 1.0
        input_constraints.fill = GridBagConstraints.BOTH
        input_constraints.insets = Insets(0, 0, 0, 6)
        action_panel.add(top_scroll_area, input_constraints)

        add_button = JButton("Add")
        add_button.setMnemonic(ord('T'))
        add_button.setToolTipText("Add the provided parameters to the Top list.")
        add_button.addActionListener(ReflectMeActionListener(self._add_top_params))

        button_constraints = GridBagConstraints()
        button_constraints.gridx = 1
        button_constraints.gridy = 0
        button_constraints.anchor = GridBagConstraints.NORTH
        button_constraints.insets = Insets(0, 0, 0, 0)
        action_panel.add(add_button, button_constraints)

        self._top_params_area.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "addTopParams")
        self._top_params_area.getActionMap().put("addTopParams", ReflectMeAbstractAction(self._add_top_params))

        panel.add(action_panel, BorderLayout.NORTH)

        self._top_params_model = TopParamsTableModel()
        self._top_params_table = JTable(self._top_params_model)
        self._top_params_table.setToolTipText("Toggle to enable or disable individual top parameters.")
        self._installTableDefaults(self._top_params_table)
        top_column = self._top_params_table.getColumnModel().getColumn(0)
        top_column.setPreferredWidth(80)
        top_column.setMaxWidth(80)
        top_column.setMinWidth(60)

        top_scroll = JScrollPane(self._top_params_table)
        top_scroll.setPreferredSize(Dimension(0, 220))
        panel.add(top_scroll, BorderLayout.CENTER)

        delete_bar = self._buildButtonBar()
        delete_button = JButton("Delete")
        delete_button.setMnemonic(ord('D'))
        delete_button.setToolTipText("Remove selected parameters.")
        delete_button.addActionListener(ReflectMeActionListener(self._delete_top_params))
        delete_bar.add(delete_button)
        panel.add(delete_bar, BorderLayout.SOUTH)

        return panel

    def _buildHeaderPanel(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 4, 10))

        title = JLabel("ReflectMe — Smart Reflection Scanner")
        try:
            font = title.getFont()
            title.setFont(font.deriveFont(font.getSize2D() + 2.0))
        except Exception:
            pass
        panel.add(title)

        subtitle = JLabel("Automated reflection checks with URL/Response/Top parameters")
        subtitle.setForeground(UIManager.getColor("Label.disabledForeground"))
        panel.add(subtitle)

        separator = JSeparator()
        separator.setAlignmentX(0.0)
        separator.setMaximumSize(Dimension(32767, separator.getPreferredSize().height))
        panel.add(Box.createVerticalStrut(6))
        panel.add(separator)

        return panel

    def _buildScannerOptionsSection(self):
        panel = JPanel(GridBagLayout())

        self._scope_checkbox = JCheckBox("Scope only")
        self._scope_checkbox.setSelected(True)
        self._scope_checkbox.setMnemonic(ord('S'))
        self._scope_checkbox.setToolTipText("Limit checks to in-scope targets.")
        self._scope_checkbox.addActionListener(ReflectMeActionListener(self._toggle_scope))

        self._extract_checkbox = JCheckBox("Extract params from response")
        self._extract_checkbox.setMnemonic(ord('E'))
        self._extract_checkbox.setToolTipText("Also test parameters discovered in response bodies.")
        self._extract_checkbox.addActionListener(ReflectMeActionListener(self._toggle_extract))

        self._check_individual_checkbox = JCheckBox("Check parameters individually")
        self._check_individual_checkbox.setMnemonic(ord('I'))
        self._check_individual_checkbox.setToolTipText("Send separate requests to verify each parameter individually.")
        self._check_individual_checkbox.addActionListener(ReflectMeActionListener(self._toggle_check_individual))

        self._use_top_params_checkbox = JCheckBox("Use Top Parameters")
        self._use_top_params_checkbox.setMnemonic(ord('U'))
        self._use_top_params_checkbox.setToolTipText("Append your Top params to the URL and/or test them when URL has no query.")
        self._use_top_params_checkbox.addActionListener(ReflectMeActionListener(self._toggle_use_top_params))

        self._auto_check_urls_without_param_checkbox = JCheckBox("Check URLs without parameter")
        self._auto_check_urls_without_param_checkbox.setSelected(True)
        self._auto_check_urls_without_param_checkbox.setMnemonic(ord('C'))
        self._auto_check_urls_without_param_checkbox.setToolTipText("Auto run extraction when URL has no query params.")
        self._auto_check_urls_without_param_checkbox.addActionListener(ReflectMeActionListener(self._toggle_auto_check_urls_without_param))

        self._debug_checkbox = JCheckBox("Debug: log search details")
        self._debug_checkbox.setSelected(True)
        self._debug_checkbox.setMnemonic(ord('D'))
        self._debug_checkbox.setToolTipText("Log detailed reflection matching information.")
        self._debug_checkbox.addActionListener(ReflectMeActionListener(self._toggle_debug))

        checkboxes = [
            self._scope_checkbox,
            self._extract_checkbox,
            self._check_individual_checkbox,
            self._use_top_params_checkbox,
            self._auto_check_urls_without_param_checkbox,
            self._debug_checkbox,
        ]

        for idx, checkbox in enumerate(checkboxes):
            constraints = GridBagConstraints()
            constraints.gridx = idx % 2
            constraints.gridy = idx // 2
            constraints.anchor = GridBagConstraints.WEST
            constraints.insets = Insets(4, 6, 4, 6)
            constraints.weightx = 0.5
            panel.add(checkbox, constraints)

        filler = GridBagConstraints()
        filler.gridx = 0
        filler.gridy = (len(checkboxes) + 1) // 2
        filler.weightx = 1.0
        filler.weighty = 1.0
        filler.gridwidth = 2
        filler.fill = GridBagConstraints.BOTH
        panel.add(JPanel(), filler)

        return panel

    def _buildPayloadLimitsSection(self):
        panel = JPanel(GridBagLayout())
        row = 0

        self._canary_field = JTextField("mmdhacker", 16)
        self._canary_field.setToolTipText("Marker inserted into payload templates.")
        self._canary_field.addActionListener(ReflectMeActionListener(self._canary_updated))
        row = self._addFormRow(panel, row, "Custom Canary:", self._canary_field)

        self._max_tests_spinner = JSpinner(SpinnerNumberModel(20, 1, 200, 1))
        self._max_tests_spinner.setToolTipText("Global cap on total requests per URL.")
        self._max_tests_spinner.addChangeListener(ReflectMeChangeListener(self._max_tests_changed))
        row = self._addFormRow(panel, row, "MAX_TESTS:", self._max_tests_spinner)

        self._chunk_spinner = JSpinner(SpinnerNumberModel(10, 1, 50, 1))
        self._chunk_spinner.setToolTipText("How many parameters to mutate per request.")
        self._chunk_spinner.addChangeListener(ReflectMeChangeListener(self._chunk_changed))
        row = self._addFormRow(panel, row, "Chunk (params per request):", self._chunk_spinner)

        self._addFormFiller(panel, row)

        return panel

    def _buildControlsSection(self):
        button_bar = self._buildButtonBar()

        self._start_button = JButton("Start")
        self._start_button.setMnemonic(ord('R'))
        self._start_button.setToolTipText("Start scanning incoming proxy traffic.")
        self._start_button.addActionListener(ReflectMeActionListener(self._start_scanner))
        button_bar.add(self._start_button)

        self._stop_button = JButton("Stop")
        self._stop_button.setMnemonic(ord('P'))
        self._stop_button.setToolTipText("Stop scanning new traffic.")
        self._stop_button.addActionListener(ReflectMeActionListener(self._stop_scanner))
        button_bar.add(self._stop_button)

        clear_button = JButton("Clear scanned URLs")
        clear_button.setMnemonic(ord('L'))
        clear_button.setToolTipText("Clear the internal list of already scanned URLs.")
        clear_button.addActionListener(ReflectMeActionListener(self._clear_scanned))
        button_bar.add(clear_button)

        container = JPanel(BorderLayout())
        container.add(button_bar, BorderLayout.EAST)
        return container

    def _buildStatusBar(self):
        panel = JPanel(BorderLayout())
        separator_color = UIManager.getColor("Separator.foreground")
        if separator_color is None:
            separator_color = UIManager.getColor("Label.foreground")
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, separator_color),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)))

        self._status_label = JLabel("Status: Stopped")
        self._status_label.setToolTipText("Current scanner state.")
        panel.add(self._status_label, BorderLayout.WEST)

        return panel

    def _addFormRow(self, panel, row, label_text, component):
        label = JLabel(label_text)
        label.setHorizontalAlignment(JLabel.RIGHT)
        label.setLabelFor(component)
        preferred = label.getPreferredSize()
        label.setPreferredSize(Dimension(180, preferred.height))

        label_constraints = GridBagConstraints()
        label_constraints.gridx = 0
        label_constraints.gridy = row
        label_constraints.anchor = GridBagConstraints.EAST
        label_constraints.insets = Insets(4, 6, 4, 6)
        panel.add(label, label_constraints)

        component_constraints = GridBagConstraints()
        component_constraints.gridx = 1
        component_constraints.gridy = row
        component_constraints.weightx = 1.0
        component_constraints.fill = GridBagConstraints.HORIZONTAL
        component_constraints.insets = Insets(4, 6, 4, 6)
        panel.add(component, component_constraints)

        return row + 1

    def _addFormFiller(self, panel, row):
        filler_constraints = GridBagConstraints()
        filler_constraints.gridx = 0
        filler_constraints.gridy = row
        filler_constraints.weightx = 1.0
        filler_constraints.weighty = 1.0
        filler_constraints.gridwidth = 2
        filler_constraints.fill = GridBagConstraints.BOTH
        panel.add(JPanel(), filler_constraints)

    def _titled(self, child, title):
        wrapper = JPanel(BorderLayout())
        wrapper.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(title),
            BorderFactory.createEmptyBorder(8, 8, 8, 8)))
        wrapper.add(child, BorderLayout.CENTER)
        return wrapper

    def _buildButtonBar(self):
        bar = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        bar.setOpaque(False)
        return bar

    def _installTableDefaults(self, table):
        try:
            table.setRowHeight(22)
            table.setFillsViewportHeight(True)
            table.setShowGrid(False)
            table.setIntercellSpacing(Dimension(0, 0))
            table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        except Exception:
            pass

    def _updateControlStates(self):
        running = bool(getattr(self, '_running', False))
        try:
            if hasattr(self, '_start_button') and self._start_button is not None:
                self._start_button.setEnabled(not running)
            if hasattr(self, '_stop_button') and self._stop_button is not None:
                self._stop_button.setEnabled(running)
        except Exception:
            pass

    def _updateStatusColor(self):
        try:
            txt = self._status_label.getText().lower()
            if 'running' in txt:
                self._status_label.setForeground(Color(0, 180, 0))
            elif 'stopped' in txt:
                self._status_label.setForeground(Color(200, 0, 0))
            else:
                self._status_label.setForeground(Color(220, 140, 0))
        except Exception:
            pass

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

    def _toggle_use_top_params(self, event):
        self._use_top_params = self._use_top_params_checkbox.isSelected()

    def _toggle_auto_check_urls_without_param(self, event):
        self._auto_check_urls_without_param = self._auto_check_urls_without_param_checkbox.isSelected()

    def _toggle_debug(self, event):
        if hasattr(self, '_debug_checkbox'):
            self._debug_verbose = self._debug_checkbox.isSelected()

    def _canary_updated(self, event):
        try:
            self._custom_canary = self._get_canary()
        except Exception:
            self._custom_canary = self._get_canary()

    def _get_canary(self):
        try:
            text = self._canary_field.getText()
            text = text.strip() if text is not None else ""
        except Exception:
            text = ""
        return text if text else "mmdhacker"

    def _max_tests_changed(self, event):
        try:
            self._max_tests = int(self._max_tests_spinner.getValue())
        except Exception:
            self._max_tests = 20

    def _get_max_tests(self):
        try:
            value = int(self._max_tests)
            if value > 0:
                return value
        except Exception:
            pass
        try:
            spinner_value = int(self._max_tests_spinner.getValue())
            return spinner_value
        except Exception:
            return 20

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
        self._updateControlStates()
        self._updateStatusColor()
        self._emit_start_test_issue()

    def _stop_scanner(self, event):
        with self._lock:
            self._running = False
            self._status_label.setText("Status: Stopped")
        self._updateControlStates()
        self._updateStatusColor()

    def _clear_scanned(self, event):
        with self._lock:
            self._scanned_urls.clear()
            self._rate_limit_counts.clear()
            self._rate_limit_blocked.clear()

    def _emit_start_test_issue(self):
        try:
            # Prefer the last seen real target (to not be filtered out)
            url = self._last_seen_url
            service = self._last_seen_service
            if url is None:
                try:
                    url = URL("http://reflectme.local/start-check")
                except Exception:
                    url = None
            if service is None:
                service = ReflectMeHttpService("reflectme.local", 80, "http")

            detail = "<p>Debug: Start button pressed. If you see this, addScanIssue works.</p>"
            issue = ReflectMeIssue(service, url,
                                   "ReflectMe Debug Start Signal",
                                   detail, self._norm_severity("Information"),
                                   self._norm_confidence("Firm"),
                                   ArrayList())
            self._log("[ReflectMe][DEBUG] start-issue severity=%r confidence=%r" % (issue.getSeverity(), issue.getConfidence()))
            try:
                self._callbacks.addScanIssue(issue)
                self._callbacks.issueAlert("ReflectMe: start signal issue added")
                self._log("[ReflectMe][DEBUG] Emitted start debug issue")
            except Exception:
                traceback.print_exc()
        except Exception:
            traceback.print_exc()

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
            # track last seen context for visible debug issue
            self._last_seen_url = url
            self._last_seen_service = messageInfo.getHttpService()
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
                self._last_content_type_decision = (None, 'no-headers')
                return False
            allowed = self._allowed_model.get_enabled_values()
            if not allowed:
                self._last_content_type_decision = (None, 'no-allowed-types')
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
                self._last_content_type_decision = (None, 'no-content-type')
                return False
            lowered = content_type.lower()
            if 'application/json' in lowered:
                self._last_content_type_decision = (content_type, 'hard-skip-json')
                return False
            for value in allowed:
                if value.lower() in lowered:
                    self._last_content_type_decision = (content_type, 'allowed-match')
                    return True
            self._last_content_type_decision = (content_type, 'not-allowed')
            return False
        except Exception:
            traceback.print_exc()
            self._last_content_type_decision = (None, 'exception')
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

            top_param_names = self._top_params_model.get_enabled_values()
            top_params = []
            top_pairs = []
            top_enabled = self._use_top_params and bool(top_param_names)
            if top_enabled:
                for name in top_param_names:
                    top_pairs.append([name, ''])
                    top_params.append({
                        'name': name,
                        'base_value': '',
                        'is_existing': False,
                        'source': 'top'
                    })
            else:
                top_param_names = []

            response_bytes = messageInfo.getResponse()
            response_raw = self._to_bytes(response_bytes)
            body_offset = response_info.getBodyOffset()
            body_bytes = response_raw[body_offset:]
            content_type = self._extract_content_type(response_info)

            extract_enabled_effective = self._extract_from_resp or (self._auto_check_urls_without_param and not has_query)
            extracted_params = []
            if extract_enabled_effective:
                extracted_names = self.extract_parameters_from_html_or_js_or_json_or_xml(body_bytes, content_type)
                for name in extracted_names:
                    extracted_params.append({
                        'name': name,
                        'base_value': '',
                        'is_existing': False,
                        'source': 'extracted'
                    })

            phases = []

            def _clone_params(params):
                clones = []
                for param in params:
                    clone = {}
                    try:
                        for key in param:
                            clone[key] = param[key]
                    except Exception:
                        pass
                    clones.append(clone)
                return clones

            def _clone_pairs(pairs):
                cloned_pairs = []
                for item in pairs:
                    try:
                        name = item[0]
                    except Exception:
                        name = None
                    try:
                        value = item[1]
                    except Exception:
                        value = ''
                    cloned_pairs.append([name, value])
                return cloned_pairs

            existing_pairs = []
            for param in existing_params:
                base_value = param.get('base_value', '')
                if base_value is None:
                    base_value = ''
                existing_pairs.append([param['name'], base_value])

            if has_query and extract_enabled_effective:
                phase_a_base = _clone_pairs(existing_pairs)
                if top_pairs:
                    phase_a_base.extend(_clone_pairs(top_pairs))
                phase_a_targets = _clone_params(existing_params)
                if phase_a_targets:
                    phases.append({
                        'name': 'url',
                        'base_query_pairs': phase_a_base,
                        'target_params': phase_a_targets
                    })
                phase_b_targets = _clone_params(extracted_params)
                if phase_b_targets:
                    phase_b_base = []
                    if top_pairs:
                        phase_b_base.extend(_clone_pairs(top_pairs))
                    phases.append({
                        'name': 'resp',
                        'base_query_pairs': phase_b_base,
                        'target_params': phase_b_targets
                    })
            elif not has_query:
                if top_enabled and top_params:
                    phase_top_targets = _clone_params(top_params)
                    if phase_top_targets:
                        phases.append({
                            'name': 'top',
                            'base_query_pairs': [],
                            'target_params': phase_top_targets
                        })
                    if extract_enabled_effective and extracted_params:
                        phase_b_targets = _clone_params(extracted_params)
                        if phase_b_targets:
                            phase_b_base = []
                            if top_pairs:
                                phase_b_base.extend(_clone_pairs(top_pairs))
                            phases.append({
                                'name': 'resp',
                                'base_query_pairs': phase_b_base,
                                'target_params': phase_b_targets
                            })
                elif extract_enabled_effective and extracted_params:
                    phase_targets = _clone_params(extracted_params)
                    if phase_targets:
                        phases.append({
                            'name': 'resp',
                            'base_query_pairs': [],
                            'target_params': phase_targets
                        })
            else:
                phase_base = _clone_pairs(existing_pairs)
                if top_pairs:
                    phase_base.extend(_clone_pairs(top_pairs))
                phase_targets = _clone_params(existing_params)
                if phase_targets:
                    phases.append({
                        'name': 'url',
                        'base_query_pairs': phase_base,
                        'target_params': phase_targets
                    })

            if not phases:
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
            tests_sent = 0
            issue_entries = []
            message_markers = {}
            modes = ['append', 'replace']
            for phase in phases:
                active_target_params = phase.get('target_params') or []
                if not active_target_params:
                    continue
                base_pairs_phase = phase.get('base_query_pairs') or []
                if self._check_individually:
                    param_sets = [[param] for param in active_target_params]
                else:
                    chunks = self._chunk_list(active_target_params, self._chunk)
                    param_sets = [list(chunk) for chunk in chunks if chunk]
                for param_set in param_sets:
                    if tests_sent >= self._get_max_tests():
                        break
                    for mode in modes:
                        if tests_sent >= self._get_max_tests():
                            break
                        for template in TEMPLATES:
                            if tests_sent >= self._get_max_tests():
                                break
                            canary = self._get_canary()
                            payload = template.replace('{CANARY}', canary)
                            base_query_pairs = _clone_pairs(base_pairs_phase)
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
                        if tests_sent >= self._get_max_tests():
                            break
                if tests_sent >= self._get_max_tests():
                    break
            if issue_entries:
                http_messages = ArrayList()
                for key in message_markers:
                    item = message_markers[key]
                    marked_msg = self._persist_and_mark(item['message'], item['markers'])
                    http_messages.add(marked_msg)

                detail = self._build_issue_detail(issue_entries)
                issue = ReflectMeIssue(service, request_info.getUrl(),
                                       "Reflected input detected (ReflectMe)",
                                       detail,
                                       self._norm_severity("Information"),
                                       self._norm_confidence("Firm"),
                                       http_messages)
                self._log("[ReflectMe][DEBUG] issue severity=%r confidence=%r" % (issue.getSeverity(), issue.getConfidence()))
                try:
                    self._callbacks.addScanIssue(issue)
                    self._callbacks.issueAlert("ReflectMe: aggregated reflection issue added")
                    self._log("[ReflectMe][DEBUG] Emitted aggregated reflection issue ({0} entries)".format(len(issue_entries)))
                except Exception:
                    traceback.print_exc()
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
            # strip our loop-prevention header if present
            if lower.startswith('x-jxr-ext'):
                continue
            # drop Accept-Encoding to enforce identity encoding
            if lower.startswith('accept-encoding'):
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
        # enforce identity encoding for reliable matching & markers
        headers.insert(0, start_line)
        headers.append('Accept-Encoding: identity')
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
            self._dump_http_transaction_raw(http_request_response, response_info, "SCAN-TEST")
            status_code = response_info.getStatusCode()
            if status_code == 429:
                self._register_rate_limit(service, rate_key, http_request_response)
            allowed_content_type = self._is_allowed_content_type(response_info)
            content_type_value = None
            decision_reason = None
            try:
                decision_info = getattr(self, '_last_content_type_decision', None)
            except Exception:
                decision_info = None
            if isinstance(decision_info, tuple) and len(decision_info) >= 2:
                content_type_value, decision_reason = decision_info[0], decision_info[1]
            if content_type_value is None:
                content_type_value = self._extract_content_type(response_info)
            payload_value = payload if payload is not None else ''
            result = self._search_payload_and_mark(http_request_response, payload_value, response_info, canary)
            if isinstance(result, dict):
                diag = result.get('diag')
                if not isinstance(diag, dict):
                    diag = {}
                    result['diag'] = diag
                diag['content_type_value'] = content_type_value or ''
                diag['content_type_allowed'] = bool(allowed_content_type)
                if decision_reason is not None:
                    diag['content_type_reason'] = decision_reason
                notes = diag.get('notes')
                if not isinstance(notes, list):
                    notes = []
                if not allowed_content_type:
                    reason_note = 'Skipped by content-type: {0}'.format(content_type_value or '(none)')
                    if decision_reason == 'hard-skip-json':
                        reason_note += ' (hard JSON skip)'
                    elif decision_reason:
                        reason_note += ' ({0})'.format(decision_reason)
                    notes.append(reason_note)
                diag['notes'] = notes
            self._dump_debug_report(http_request_response, response_info, result, payload_value)
            if not allowed_content_type:
                return False
            if not result.get('found'):
                diag = result.get('diag', {}) if isinstance(result, dict) else {}
                raw_canary_found = diag.get('raw_canary_found') if isinstance(diag, dict) else False
                if raw_canary_found:
                    try:
                        body_offset = diag.get('body_offset', response_info.getBodyOffset())
                    except Exception:
                        body_offset = response_info.getBodyOffset()
                    index_hint = diag.get('raw_canary_index') if isinstance(diag, dict) else None
                    self._debug_near_miss(response_bytes, body_offset, canary, index_hint)
                return False

            # Track message and markers (raw matches only)
            base_msg = http_request_response
            key = id(base_msg)
            if key not in message_markers:
                message_markers[key] = {'message': base_msg, 'markers': []}
            for m in result.get('markers', []):
                message_markers[key]['markers'].append(m)

            content_type = self._extract_content_type(response_info)
            snippet = result.get('snippet', '')
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
            # Emit a quick confirm issue on first detection to guarantee visibility
            try:
                if allowed_content_type and not getattr(self, '_emitted_first_reflect_issue', False):
                    # persist + mark the same traffic to make it visible in UI and sitemap
                    quick_marked = self._persist_and_mark(http_request_response, result.get('markers', []))
                    try:
                        analyzed_req = self._helpers.analyzeRequest(quick_marked)
                        quick_url = analyzed_req.getUrl() if analyzed_req is not None else None
                    except Exception:
                        quick_url = None

                    snippet_html = self._html_escape(result.get('snippet', ''))
                    micro_detail = "<p>Quick confirm: payload reflected.</p><pre>{0}</pre>".format(snippet_html)

                    quick_msgs = ArrayList()
                    quick_msgs.add(quick_marked)

                    quick_issue = ReflectMeIssue(
                        quick_marked.getHttpService() if hasattr(quick_marked, 'getHttpService') else service,
                        quick_url,
                        "Reflected input detected (ReflectMe)",
                        micro_detail,
                        self._norm_severity("Information"),
                        self._norm_confidence("Firm"),
                        quick_msgs
                    )
                    try:
                        self._callbacks.addScanIssue(quick_issue)
                        self._callbacks.issueAlert("ReflectMe: reflection detected at %s" % (str(quick_url) if quick_url else "(unknown URL)"))
                        self._emitted_first_reflect_issue = True
                        self._log("[ReflectMe][DEBUG] Quick confirm issue emitted")
                    except Exception:
                        traceback.print_exc()
            except Exception:
                traceback.print_exc()
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
                messages = ArrayList()
                messages.add(self._callbacks.saveBuffersToTempFiles(http_request_response))
                issue = ReflectMeIssue(service, url,
                                       "ReflectMe: received >5 responses with HTTP 429 (Too Many Requests) — testing suspended for this target/timeframe.",
                                       detail,
                                       self._norm_severity("Information"),
                                       self._norm_confidence("Firm"),
                                       messages)
                self._log("[ReflectMe][DEBUG] rate-limit issue severity=%r confidence=%r" % (issue.getSeverity(), issue.getConfidence()))
                try:
                    self._callbacks.addScanIssue(issue)
                except Exception:
                    traceback.print_exc()

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

    def _search_payload_and_mark(self, http_request_response, payload, response_info, canary):
        result = {'found': False, 'markers': [], 'snippet': u'', 'diag': {}}
        try:
            resp_bytes = http_request_response.getResponse()
            if resp_bytes is None:
                result['diag'] = {'error': 'no_response'}
                return result

            try:
                body_offset = response_info.getBodyOffset()
            except Exception:
                body_offset = 0

            enc_value = self._get_header_value(response_info, 'content-encoding')
            enc_lower = enc_value.lower() if enc_value else ''

            try:
                payload_bytes_java = self._helpers.stringToBytes(payload)
            except Exception:
                payload_bytes_java = None
            payload_bytes_py = self._to_bytes(payload_bytes_java) if payload_bytes_java is not None else ''
            payload_len = len(payload_bytes_java) if payload_bytes_java is not None else 0

            diag = {
                'body_offset': body_offset,
                'content_encoding': enc_value or '',
                'identity_encoding': (not enc_lower) or ('identity' in enc_lower),
                'payload': payload,
                'payload_length': payload_len,
                'payload_urlencoded': '',
                'payload_htmlencoded': self._html_escape(payload if payload is not None else ''),
                'raw_found': False,
                'raw_first_index': -1,
                'raw_first_index_all': -1,
                'raw_markers_count': 0,
                'raw_snippet': u'',
                'raw_canary_found': False,
                'raw_canary_index': -1,
                'raw_canary_index_first': -1,
                'raw_canary_index_all': -1,
                'raw_canary_snippet': u'',
                'was_compressed': False,
                'decomp_found_exact': False,
                'decomp_exact_index': -1,
                'decomp_found_urlenc': False,
                'decomp_urlenc_index': -1,
                'decomp_found_htmlenc': False,
                'decomp_htmlenc_index': -1,
                'decomp_snippet_exact': u'',
                'decomp_snippet_urlenc': u'',
                'decomp_snippet_htmlenc': u'',
                'notes': [],
                'adjacency_used': False,
                'adjacent_char': '',
                'adjacent_side': '',
                'adjacency_markers_count': 0,
                'adjacency_first_index': -1
            }

            try:
                diag['payload_urlencoded'] = self._safe_to_unicode(self._helpers.urlEncode(payload if payload is not None else ''))
            except Exception:
                diag['payload_urlencoded'] = ''

            def _build_snippet(raw_str, index, length, window=60):
                if raw_str is None or index is None:
                    return u''
                try:
                    if index < 0:
                        return u''
                    start = max(0, int(index) - window)
                    end = min(len(raw_str), int(index) + int(length) + window)
                    segment = raw_str[start:end]
                    return self._safe_to_unicode(segment)
                except Exception:
                    return u''

            def _clip(text, limit=160):
                if text is None:
                    return u''
                try:
                    length = len(text)
                except Exception:
                    try:
                        text = self._safe_to_unicode(text)
                        length = len(text)
                    except Exception:
                        return u''
                if length > limit:
                    try:
                        return text[:limit] + u'…'
                    except Exception:
                        return text
                return text

            total_len = len(resp_bytes)
            resp_raw = self._to_bytes(resp_bytes)
            raw_markers = []
            first_payload_index = None
            raw_index_body = -1
            raw_index_all = -1
            if payload_len > 0 and payload_bytes_java is not None:
                try:
                    raw_index_body = self._helpers.indexOf(resp_bytes, payload_bytes_java, True, body_offset, total_len)
                except Exception:
                    raw_index_body = -1
                diag['raw_first_index'] = raw_index_body
                try:
                    raw_index_all = self._helpers.indexOf(resp_bytes, payload_bytes_java, True, 0, total_len)
                except Exception:
                    raw_index_all = -1
                diag['raw_first_index_all'] = raw_index_all

            if payload_len > 0 and payload_bytes_py:
                search_pos = max(body_offset, 0)
                while True:
                    idx_py = resp_raw.find(payload_bytes_py, search_pos)
                    if idx_py == -1:
                        break
                    if idx_py < body_offset:
                        search_pos = idx_py + 1
                        continue
                    raw_markers.append([int(idx_py), int(idx_py + payload_len)])
                    if first_payload_index is None:
                        first_payload_index = idx_py
                    search_pos = idx_py + payload_len if payload_len > 0 else idx_py + 1

            diag['raw_markers_count'] = len(raw_markers)
            if first_payload_index is not None:
                diag['raw_found'] = True
                snippet = _build_snippet(resp_raw, first_payload_index, payload_len)
                diag['raw_snippet'] = _clip(snippet)
                result['snippet'] = snippet
                if raw_index_body == -1 and raw_index_all != -1 and raw_index_all >= body_offset:
                    try:
                        diag['notes'].append('Fallback raw search matched at index {0}'.format(raw_index_all))
                    except Exception:
                        pass
            else:
                diag['raw_markers_count'] = 0

            special_chars = ['<', '>', '"', "'", '`']
            adjacency_markers = []
            adjacency_first_index = -1
            adjacency_char = ''
            adjacency_side = ''
            canary_len = 0
            canary_bytes_java = None
            canary_bytes_py = ''
            if canary:
                try:
                    canary_bytes_java = self._helpers.stringToBytes(canary)
                except Exception:
                    canary_bytes_java = None
                canary_bytes_py = self._to_bytes(canary_bytes_java) if canary_bytes_java is not None else ''
                try:
                    canary_len = len(canary_bytes_py)
                except Exception:
                    canary_len = 0
            if canary_len > 0 and canary_bytes_java is not None:
                try:
                    canary_index_all = self._helpers.indexOf(resp_bytes, canary_bytes_java, True, 0, total_len)
                except Exception:
                    canary_index_all = -1
                diag['raw_canary_index_all'] = canary_index_all
            if canary_len > 0 and canary_bytes_py:
                search_pos = max(body_offset, 0)
                while True:
                    idx_canary = resp_raw.find(canary_bytes_py, search_pos)
                    if idx_canary == -1:
                        break
                    if idx_canary < body_offset:
                        search_pos = idx_canary + 1
                        continue
                    if diag['raw_canary_index_first'] == -1:
                        diag['raw_canary_index_first'] = idx_canary
                    if diag['raw_canary_index'] == -1:
                        diag['raw_canary_index'] = idx_canary
                    diag['raw_canary_found'] = True
                    if not diag['raw_canary_snippet']:
                        diag['raw_canary_snippet'] = _clip(_build_snippet(resp_raw, idx_canary, canary_len))
                    left_idx = idx_canary - 1
                    right_idx = idx_canary + canary_len
                    marker_added = False
                    side_used = ''
                    char_used = ''
                    if left_idx >= body_offset and left_idx >= 0:
                        try:
                            left_char = resp_raw[left_idx]
                        except Exception:
                            left_char = None
                        if left_char in special_chars:
                            marker_added = True
                            side_used = 'left'
                            char_used = left_char
                    if (not marker_added) and right_idx < len(resp_raw) and right_idx >= body_offset:
                        try:
                            right_char = resp_raw[right_idx]
                        except Exception:
                            right_char = None
                        if right_char in special_chars:
                            marker_added = True
                            side_used = 'right'
                            char_used = right_char
                    if marker_added:
                        adjacency_markers.append([int(idx_canary), int(idx_canary + canary_len)])
                        if adjacency_first_index == -1:
                            adjacency_first_index = idx_canary
                            adjacency_char = char_used
                            adjacency_side = side_used
                    if canary_len > 0:
                        search_pos = idx_canary + canary_len
                    else:
                        search_pos = idx_canary + 1
                diag['adjacency_markers_count'] = len(adjacency_markers)
                if adjacency_first_index != -1:
                    diag['adjacency_first_index'] = adjacency_first_index
                    diag['adjacent_char'] = adjacency_char or ''
                    diag['adjacent_side'] = adjacency_side or ''
            else:
                diag['adjacency_markers_count'] = 0

            raw_body = resp_raw[body_offset:]
            search_body, was_decomp = self._decompress_if_needed(raw_body, response_info)
            diag['was_compressed'] = bool(was_decomp)
            if was_decomp:
                try:
                    diag['decompressed_length'] = len(search_body)
                except Exception:
                    diag['decompressed_length'] = 0
                if payload_len > 0 and payload_bytes_py is not None:
                    try:
                        idx = search_body.find(payload_bytes_py)
                    except Exception:
                        idx = -1
                    diag['decomp_exact_index'] = idx
                    if idx != -1:
                        diag['decomp_found_exact'] = True
                        diag['decomp_snippet_exact'] = _clip(_build_snippet(search_body, idx, payload_len))
                payload_url = diag.get('payload_urlencoded', '') or ''
                if payload_url:
                    try:
                        idx_url = search_body.find(payload_url)
                    except Exception:
                        idx_url = -1
                    diag['decomp_urlenc_index'] = idx_url
                    if idx_url != -1:
                        diag['decomp_found_urlenc'] = True
                        diag['decomp_snippet_urlenc'] = _clip(_build_snippet(search_body, idx_url, len(payload_url)))
                payload_html = diag.get('payload_htmlencoded', '') or ''
                if payload_html:
                    try:
                        idx_html = search_body.find(payload_html)
                    except Exception:
                        idx_html = -1
                    diag['decomp_htmlenc_index'] = idx_html
                    if idx_html != -1:
                        diag['decomp_found_htmlenc'] = True
                        diag['decomp_snippet_htmlenc'] = _clip(_build_snippet(search_body, idx_html, len(payload_html)))

            if diag['raw_found'] and not diag['identity_encoding']:
                diag['notes'].append('Raw match present but response declared compressed encoding')
            if payload_len == 0:
                diag['notes'].append('Empty payload supplied; skipping raw search')

            found = False
            markers_to_use = []
            if payload_len > 0 and diag['identity_encoding'] and raw_markers:
                found = True
                markers_to_use = raw_markers
            elif adjacency_markers and diag['identity_encoding']:
                found = True
                markers_to_use = adjacency_markers
                diag['adjacency_used'] = True
                if adjacency_first_index != -1:
                    snippet = _build_snippet(resp_raw, adjacency_first_index, canary_len)
                    if snippet:
                        result['snippet'] = snippet
                    diag['raw_canary_snippet'] = _clip(_build_snippet(resp_raw, adjacency_first_index, canary_len))
                diag['notes'].append('Adjacency rule triggered (special-char neighbour: {0}, side: {1})'.format(
                    adjacency_char or '', adjacency_side or ''))
            else:
                diag['adjacency_used'] = False

            if found:
                result['found'] = True
                result['markers'] = markers_to_use
                if not result['snippet']:
                    if markers_to_use:
                        first_idx = markers_to_use[0][0]
                        if markers_to_use is raw_markers:
                            length = payload_len
                        else:
                            length = canary_len
                        snippet = _build_snippet(resp_raw, first_idx, length)
                        result['snippet'] = snippet
            else:
                result['markers'] = []
                if not result['snippet']:
                    result['snippet'] = u''

            result['diag'] = diag
            return result
        except Exception:
            traceback.print_exc()
            result['diag'] = {'error': 'exception'}
            return result

    def _debug_near_miss(self, resp_bytes, body_offset, canary, index_hint=None):
        try:
            if not self._debug_verbose:
                return
            if resp_bytes is None or not canary:
                return
            canary_pat = self._helpers.stringToBytes(canary)
            if canary_pat is None:
                return
            total_len = len(resp_bytes)
            if index_hint is None or index_hint < 0:
                idx = self._helpers.indexOf(resp_bytes, canary_pat, True, body_offset, total_len)
            else:
                idx = index_hint
            if idx == -1:
                return
            resp_raw = self._to_bytes(resp_bytes)
            canary_raw = self._to_bytes(canary_pat)
            start = max(0, idx - 60)
            end = min(len(resp_raw), idx + len(canary_raw) + 60)
            window = resp_raw[start:end]
            preview = self._safe_to_unicode(window)
            self._log("[ReflectMe][DEBUG] Near-miss canary window: {0}".format(repr(preview)))
        except Exception:
            pass

    def _dump_http_transaction_raw(self, http_request_response, response_info, label):
        try:
            if not getattr(self, '_debug_verbose', False):
                return
            req_bytes = http_request_response.getRequest()
            resp_bytes = http_request_response.getResponse()

            req_info = self._helpers.analyzeRequest(http_request_response) if req_bytes is not None else None
            resp_info = response_info
            if resp_info is None and resp_bytes is not None:
                try:
                    resp_info = self._helpers.analyzeResponse(resp_bytes)
                except Exception:
                    resp_info = None

            req_hdrs = []
            if req_info is not None:
                for h in (req_info.getHeaders() or []):
                    req_hdrs.append(self._safe_to_unicode(h))

            resp_hdrs = []
            body_off = 0
            if resp_info is not None:
                for h in (resp_info.getHeaders() or []):
                    resp_hdrs.append(self._safe_to_unicode(h))
                try:
                    body_off = int(resp_info.getBodyOffset())
                except Exception:
                    body_off = 0

            max_dump = int(getattr(self, '_debug_max_dump', 4000))
            resp_raw = self._to_bytes(resp_bytes) if resp_bytes is not None else ''
            body_preview = resp_raw[body_off: body_off + max_dump]

            lines = []
            lines.append("[ReflectMe][RAW] ===== {} =====".format(label))
            if req_hdrs:
                lines.append("-- REQUEST --")
                lines.append("\n".join(req_hdrs))
            if resp_hdrs:
                lines.append("-- RESPONSE HEADERS --")
                lines.append("\n".join(resp_hdrs))
            lines.append("-- RESPONSE BODY (first {} bytes) --".format(max_dump))
            lines.append(self._safe_to_unicode(body_preview))
            lines.append("[ReflectMe][RAW END] =====================")
            self._log("\n".join(lines))
        except Exception:
            traceback.print_exc()

    def _dump_debug_report(self, http_request_response, response_info, result, payload):
        if not self._debug_verbose:
            return
        try:
            diag = result.get('diag', {}) if isinstance(result, dict) else {}

            try:
                status_code = response_info.getStatusCode()
            except Exception:
                status_code = 'unknown'

            try:
                body_offset = diag.get('body_offset', response_info.getBodyOffset())
            except Exception:
                body_offset = 0

            content_encoding = diag.get('content_encoding')
            if not content_encoding:
                try:
                    content_encoding = self._get_header_value(response_info, 'content-encoding')
                except Exception:
                    content_encoding = ''

            def _make_serializable(value):
                try:
                    basestring
                    string_types = (basestring,)
                except NameError:
                    string_types = (str,)
                if isinstance(value, string_types):
                    return self._safe_to_unicode(value)
                try:
                    number_types = (int, long, float, bool)
                except NameError:
                    number_types = (int, float, bool)
                if isinstance(value, number_types) or value is None:
                    return value
                try:
                    if isinstance(value, dict):
                        out = {}
                        for k, v in value.iteritems():
                            out[self._safe_to_unicode(k)] = _make_serializable(v)
                        return out
                except Exception:
                    pass
                try:
                    if isinstance(value, (list, tuple)):
                        return [_make_serializable(v) for v in value]
                except Exception:
                    pass
                try:
                    return self._safe_to_unicode(value)
                except Exception:
                    try:
                        return str(value)
                    except Exception:
                        return ''

            serializable_diag = {}
            if isinstance(diag, dict):
                try:
                    for key, value in diag.iteritems():
                        serializable_diag[self._safe_to_unicode(key)] = _make_serializable(value)
                except Exception:
                    try:
                        for key in diag:
                            serializable_diag[self._safe_to_unicode(key)] = _make_serializable(diag[key])
                    except Exception:
                        serializable_diag = {}

            try:
                diag_text = json.dumps(serializable_diag, ensure_ascii=False)
            except Exception:
                try:
                    diag_text = self._safe_to_unicode(serializable_diag)
                except Exception:
                    diag_text = ''

            try:
                headers = response_info.getHeaders()
                if headers is None:
                    headers = []
            except Exception:
                headers = []

            resp_bytes = http_request_response.getResponse()
            resp_raw = self._to_bytes(resp_bytes) if resp_bytes is not None else ''
            raw_preview = ''
            if resp_raw:
                end_index = body_offset + int(getattr(self, '_debug_max_dump', 4000))
                raw_preview = resp_raw[body_offset:end_index]
            raw_preview_unicode = self._safe_to_unicode(raw_preview)

            decomp_preview_unicode = ''
            if isinstance(diag, dict) and diag.get('was_compressed'):
                raw_body = resp_raw[body_offset:]
                search_body, was_decomp = self._decompress_if_needed(raw_body, response_info)
                if was_decomp and search_body:
                    max_len = int(getattr(self, '_debug_max_dump', 4000))
                    decomp_preview = search_body[:max_len]
                    decomp_preview_unicode = self._safe_to_unicode(decomp_preview)

            try:
                payload_display = self._safe_to_unicode(payload)
            except Exception:
                payload_display = ''

            snippet_display = result.get('snippet', u'') if isinstance(result, dict) else u''
            snippet_display = self._safe_to_unicode(snippet_display)

            lines = []
            lines.append("[ReflectMe][DEBUG] === SEARCH START ===")
            lines.append("Status: {0}".format(status_code))
            lines.append("Content-Encoding: {0}".format(content_encoding if content_encoding else '(none)'))
            lines.append("Body offset: {0}".format(body_offset))
            lines.append("Payload: {0}".format(repr(payload_display)))
            lines.append("RAW reflection result: {0}".format(bool(result.get('found')) if isinstance(result, dict) else False))
            lines.append("Raw match detected: {0}".format(bool(diag.get('raw_found')) if isinstance(diag, dict) else False))
            lines.append("Diagnostics: {0}".format(self._safe_to_unicode(diag_text)))
            notes = []
            if isinstance(diag, dict):
                notes = diag.get('notes', []) or []
            if notes:
                try:
                    lines.append("Notes: {0}".format(self._safe_to_unicode(', '.join([self._safe_to_unicode(n) for n in notes]))))
                except Exception:
                    pass
            lines.append("Response headers:")
            for header in headers:
                try:
                    header_text = self._safe_to_unicode(header)
                except Exception:
                    header_text = str(header)
                lines.append("  {0}".format(header_text))
            lines.append("Raw body preview (first {0} bytes):".format(int(getattr(self, '_debug_max_dump', 4000))))
            lines.append(raw_preview_unicode)
            if decomp_preview_unicode:
                lines.append("Decompressed body preview (first {0} bytes):".format(int(getattr(self, '_debug_max_dump', 4000))))
                lines.append(decomp_preview_unicode)
            if snippet_display:
                lines.append("Snippet: {0}".format(repr(snippet_display)))
            lines.append("[ReflectMe][DEBUG] === SEARCH END ===")
            self._log('\n'.join(lines))
        except Exception:
            traceback.print_exc()

    def _chunk_list(self, data, size):
        chunks = []
        if size <= 0:
            size = 1
        for i in range(0, len(data), size):
            chunks.append(data[i:i + size])
        return chunks

    def _to_bytes(self, data):
        """
        Convert Burp/Java byte[] or Python/Jython str/unicode into a Python 'str' of raw bytes.
        Never use Java .toString() on byte[].
        """
        if data is None:
            return ''
        # Fast path: if it's already a Python/Jython string, return as-is
        try:
            # In Jython 2.7, 'str' is unicode; that's OK for ASCII payloads; we treat it as a byte sequence here.
            if isinstance(data, basestring):
                return data
        except NameError:
            # Py3 on Jython isn't used, but keep compatibility
            if isinstance(data, str):
                return data
        # Try to iterate java byte[] and build bytes safely
        try:
            out = []
            for b in data:
                # java byte is signed; map to 0..255
                out.append(chr((b + 256) % 256))
            return ''.join(out)
        except Exception:
            pass
        # Last resort
        try:
            return str(data)
        except Exception:
            return ''

    def _get_header_value(self, response_info, key_lower):
        try:
            headers = response_info.getHeaders()
            if headers is None:
                return None
            kl = key_lower.lower()
            for h in headers:
                if h is None:
                    continue
                hl = h.lower()
                if hl.startswith(kl + ":"):
                    parts = h.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
            return None
        except Exception:
            return None

    def _decompress_if_needed(self, raw_body_bytes, response_info):
        """
        raw_body_bytes: Python str of bytes (as produced by _to_bytes)
        Returns: (search_body_bytes, is_decompressed_bool)
        """
        try:
            enc = self._get_header_value(response_info, "content-encoding")
            if not enc:
                return raw_body_bytes, False
            enc_l = enc.lower()
            data = raw_body_bytes
            # Use zlib so we don't fight with Java streams in Jython.
            if "gzip" in enc_l:
                try:
                    # 16+MAX_WBITS tells zlib to expect a gzip header.
                    out = zlib.decompress(data, 16 + zlib.MAX_WBITS)
                    return out, True
                except Exception:
                    return raw_body_bytes, False
            if "deflate" in enc_l:
                try:
                    # -MAX_WBITS handles raw deflate streams.
                    out = zlib.decompress(data, -zlib.MAX_WBITS)
                    return out, True
                except Exception:
                    # Some servers send zlib-wrapped deflate
                    try:
                        out = zlib.decompress(data)
                        return out, True
                    except Exception:
                        return raw_body_bytes, False
            return raw_body_bytes, False
        except Exception:
            return raw_body_bytes, False

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
