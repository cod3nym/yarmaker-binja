from .qt import QtGui


def format(color, style=''):
    """
    Return a QTextCharFormat with the given attributes.
    """
    _color = QtGui.QColor(color)

    _format = QtGui.QTextCharFormat()
    _format.setForeground(_color)
    if 'bold' in style:
        _format.setFontWeight(QtGui.QFont.Weight.Bold)
    if 'italic' in style:
        _format.setFontItalic(True)

    return _format


class LightThemeColors:
    Red = "#B71C1C"
    Pink = "#FCE4EC"
    Purple = "#4A148C"
    DeepPurple = "#311B92"
    Indigo = "#1A237E"
    Blue = "#0D47A1"
    LightBlue = "#01579B"
    Cyan = "#006064"
    Teal = "#004D40"
    Green = "#1B5E20"
    LightGreen = "#33691E"
    Lime = "#827717"
    Yellow = "#F57F17"
    Amber = "#FF6F00"
    Orange = "#E65100"
    DeepOrange = "#BF360C"
    Brown = "#3E2723"
    Grey = "#212121"
    BlueGrey = "#263238"


LIGHT_STYLES = {
    'keyword': format(LightThemeColors.LightBlue, 'bold'),
    'operator': format(LightThemeColors.Red, 'bold'),
    'brace': format(LightThemeColors.Purple),
    'rule': format(LightThemeColors.Indigo, 'bold'),
    'string': format(LightThemeColors.Amber),
    'comment': format(LightThemeColors.Green, 'italic'),
    'numbers': format(LightThemeColors.Grey),
    'wildcard': format(LightThemeColors.Blue),
}


class DarkThemeColors:
    Red = "#EF9A9A"
    Purple = "#CE93D8"
    Indigo = "#9FA8DA"
    LightBlue = "#81D4FA"
    Blue = "#90CAF9"
    Green = "#A5D6A7"
    Amber = "#FFD54F"
    Grey = "#E0E0E0"


DARK_STYLES = {
    'keyword': format(DarkThemeColors.LightBlue, 'bold'),
    'operator': format(DarkThemeColors.Red, 'bold'),
    'brace': format(DarkThemeColors.Purple),
    'rule': format(DarkThemeColors.Indigo, 'bold'),
    'string': format(DarkThemeColors.Amber),
    'comment': format(DarkThemeColors.Green, 'italic'),
    'numbers': format(DarkThemeColors.Grey),
    'wildcard': format(DarkThemeColors.Blue),
}


def styles_for_palette(palette=None) -> dict:
    """Pick colors readable on the current (Binary Ninja) theme"""
    if palette is None:
        return LIGHT_STYLES
    base = palette.color(QtGui.QPalette.ColorRole.Base)
    return DARK_STYLES if base.lightness() < 128 else LIGHT_STYLES
