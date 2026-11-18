from .qt import QtWidgets

from .components import Button


class ClosableDialog(QtWidgets.QDialog):
    def __init__(
        self,
        title: str = "Dialog",
        width: int = 800,
        height: int = 600,
        top_left_items: list | None = None,
        top_right_items: list | None = None,
        body_items: list | None = None,
        bottom_left_items: list | None = None,
        bottom_right_items: list | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(width, height)
        self._build_dialog(
            top_left_items or [],
            top_right_items or [],
            body_items or [],
            bottom_left_items or [],
            bottom_right_items or [],
        )

    def handle_close_click(self):
        self.close()

    def _build_dialog(
        self, top_left: list, top_right: list, body: list, bottom_left: list, bottom_right: list
    ):
        self.close_btn = Button("OK", self.handle_close_click)

        self.top_layout = QtWidgets.QHBoxLayout()
        for element in top_left:
            self.top_layout.addWidget(element)
        self.top_layout.addStretch()
        for element in top_right:
            self.top_layout.addWidget(element)

        self.main_layout = QtWidgets.QVBoxLayout(self)
        self.main_layout.addLayout(self.top_layout)

        for element in body:
            self.main_layout.addWidget(element)

        self.bottom_layout = QtWidgets.QHBoxLayout()
        for element in bottom_left:
            self.bottom_layout.addWidget(element)
        self.bottom_layout.addStretch()
        for element in bottom_right:
            self.bottom_layout.addWidget(element)
        self.bottom_layout.addWidget(self.close_btn)
        self.main_layout.addLayout(self.bottom_layout)
