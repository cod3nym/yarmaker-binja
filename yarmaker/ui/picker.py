"""Searchable multi-selection list.

Binary Ninja's Strings and Symbols sidebars do not expose their selection to
plugins, so strings and functions are picked from this dialog instead
(counterpart of IDA's Strings / Functions window actions).
"""
from typing import Any, Callable, List, Sequence

from .qt import QtCore, QtGui, QtWidgets
from .components import Button


class PickerDialog(QtWidgets.QDialog):
    def __init__(
            self,
            title: str,
            columns: Sequence[str],
            rows: List[Sequence[str]],
            payloads: List[Any],
            on_accept: Callable[[List[Any]], None],
            accept_label: str = 'Generate',
            numeric_columns: Sequence[int] = (),
            preselected: Sequence[int] = (),
            parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 600)
        self.payloads = payloads
        self.on_accept = on_accept

        self.model = QtGui.QStandardItemModel(len(rows), len(columns), self)
        self.model.setHorizontalHeaderLabels(list(columns))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QtGui.QStandardItem(str(value))
                item.setEditable(False)
                item.setData(row, QtCore.Qt.ItemDataRole.UserRole)
                if column in numeric_columns:
                    try:
                        sort_key = int(str(value), 0)
                    except ValueError:
                        sort_key = 0
                    item.setData(sort_key, QtCore.Qt.ItemDataRole.UserRole + 1)
                else:
                    item.setData(str(value).lower(), QtCore.Qt.ItemDataRole.UserRole + 1)
                self.model.setItem(row, column, item)

        self.proxy = QtCore.QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSortRole(QtCore.Qt.ItemDataRole.UserRole + 1)

        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText('Filter (substring, any column)')
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.proxy.setFilterFixedString)
        self.filter_edit.textChanged.connect(self._update_status)

        self.view = QtWidgets.QTableView()
        self.view.setModel(self.proxy)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setSortingEnabled(True)
        self.view.sortByColumn(0, QtCore.Qt.SortOrder.AscendingOrder)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(self.fontMetrics().height() + 4)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.setWordWrap(False)
        self.view.doubleClicked.connect(lambda *_: self._accept())
        self.view.selectionModel().selectionChanged.connect(self._update_status)
        self.view.resizeColumnsToContents()

        self.status = QtWidgets.QLabel()
        self.accept_btn = Button(accept_label, self._accept)
        self.accept_btn.setDefault(True)
        cancel_btn = Button('Cancel', self.close)

        bottom = QtWidgets.QHBoxLayout()
        bottom.addWidget(self.status)
        bottom.addStretch()
        bottom.addWidget(self.accept_btn)
        bottom.addWidget(cancel_btn)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.filter_edit)
        layout.addWidget(self.view)
        layout.addLayout(bottom)

        for row in preselected:
            index = self.proxy.mapFromSource(self.model.index(row, 0))
            self.view.selectionModel().select(
                index,
                QtCore.QItemSelectionModel.SelectionFlag.Select
                | QtCore.QItemSelectionModel.SelectionFlag.Rows)
        self._update_status()

    def selected_payloads(self) -> List[Any]:
        rows = sorted({
            self.proxy.mapToSource(index).row()
            for index in self.view.selectionModel().selectedRows()
        })
        return [self.payloads[row] for row in rows]

    def _update_status(self, *_):
        selected = len(self.view.selectionModel().selectedRows())
        self.status.setText(
            f'{self.proxy.rowCount()} of {self.model.rowCount()} shown, {selected} selected')
        self.accept_btn.setEnabled(selected > 0)

    def _accept(self):
        payloads = self.selected_payloads()
        if not payloads:
            return
        self.close()
        self.on_accept(payloads)
