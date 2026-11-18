from .highlighter import YaraHighlighter

from .qt import QtGui, QtWidgets


class Checkbox(QtWidgets.QCheckBox):
    def __init__(
            self,
            label: str,
            default: bool = False,
            on_click=None):
        super().__init__(label)

        self.setChecked(default)
        if on_click:
            self.clicked.connect(on_click)

    def is_checked(self) -> bool:
        return self.isChecked()


class ComboBox(QtWidgets.QComboBox):
    def __init__(
            self,
            items: list[tuple[str, int]],
            default: int | None = None,
            on_change=None):
        super().__init__()

        for label, data in items:
            self.addItem(label, data)

        index = self.findData(default)
        if index >= 0:
            self.setCurrentIndex(index)
        if on_change:
            self.currentIndexChanged.connect(on_change)

    def value(self) -> int:
        return self.currentData()


class Button(QtWidgets.QPushButton):
    def __init__(self, label: str, on_click=None, width: int = 100):
        super().__init__(label)

        self.setFixedWidth(width)
        if on_click:
            self.clicked.connect(on_click)


class NumberInput(QtWidgets.QSpinBox):
    def __init__(
            self,
            default: int | None = None,
            min_value: int = 0,
            max_value: int = 100,
            step: int = 1,
            on_change=None):

        super().__init__()
        self.setSingleStep(step)
        self.setFixedWidth(48)
        self.setRange(min_value, max_value)
        if default and ((default - min_value) % step == 0):
            self.setValue(default)
        if on_change:
            self.valueChanged.connect(on_change)


class Label(QtWidgets.QLabel):
    pass


def monospace_font(widget=None) -> QtGui.QFont:
    try:
        from binaryninjaui import getMonospaceFont
        return getMonospaceFont(widget)
    except Exception:
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        font.setStyleHint(QtGui.QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(10)
        return font


class YaraTextEdit(QtWidgets.QPlainTextEdit):
    def __init__(self, default: str, highlighting: bool = True):
        super().__init__(None)

        if highlighting:
            self.highlighter = YaraHighlighter(self.document(), self.palette())

        font = monospace_font(self)
        self.setFont(font)
        self.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap)

        metrics = QtGui.QFontMetrics(font)
        self.setTabStopDistance(4 * metrics.horizontalAdvance(' '))
        self.set_content(default)

    def set_content(self, text: str):
        # keep the scroll position when the rule is rebuilt
        vertical = self.verticalScrollBar().value()
        horizontal = self.horizontalScrollBar().value()
        self.setPlainText(text)
        self.verticalScrollBar().setValue(vertical)
        self.horizontalScrollBar().setValue(horizontal)
