"""Keep non-modal windows alive (and parented to the Binary Ninja main window)"""
from .qt import QtCore, QtWidgets

_open_windows = set()


def main_window():
    try:
        from binaryninjaui import UIContext
        context = UIContext.activeContext()
        if context is not None:
            return context.mainWindow()
    except Exception:
        pass
    return QtWidgets.QApplication.activeWindow()


def show_window(window: QtWidgets.QWidget):
    """Show a window, holding a reference until it is closed"""
    _open_windows.add(window)
    window.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose, True)
    window.destroyed.connect(lambda *_: _open_windows.discard(window))
    window.show()
    window.raise_()
    window.activateWindow()
    return window
