"""Binary Ninja integration: commands, rule generation and the rule editor.

Port of the IDA ``yarmaker.py`` plugin entry point.
"""
import functools
import re
import traceback
from itertools import chain
from typing import Callable, Iterable, List, Optional

import binaryninja as bn
from binaryninja import BinaryView, Function, PluginCommand
from binaryninja.mainthread import execute_on_main_thread, is_main_thread
from binaryninja.plugin import BackgroundTaskThread

from . import config
from . import binja as utils
from .adapter import YaraExtractor
from .types import Wildcard
from .yara import RuleBuilder, RulesetBuilder


PLUGIN_NAME = 'YarMaker'
MENU = 'YarMaker'

CMD_RULE = f'{MENU}\\Generate Rule from Selection'
CMD_STRINGS = f'{MENU}\\Generate Rule from Strings...'
CMD_FUNCTIONS = f'{MENU}\\Generate Ruleset from Functions...'
CMD_FUNCTION = f'{MENU}\\Generate Ruleset for Current Function'
CMD_ALL_FUNCTIONS = f'{MENU}\\Generate Ruleset for All Functions'


def log_info(message: str):
    bn.log_info(message, PLUGIN_NAME)


def log_error(message: str):
    bn.log_error(message, PLUGIN_NAME)


# --- rule generation (UI independent) ---

def generate_rule(bv: BinaryView, name: str, entities: Iterable) -> RuleBuilder:
    # YARA rule names need more than 3 chars (RuleBuilder.sanitize_rule_name)
    if len(re.sub(r'[^0-9a-zA-Z_]+', '_', name)) <= 3:
        name = f'rule_{name}'

    rule = RuleBuilder(
        name,
        show_comments=config.DEFAULT_SHOW_COMMENTS,
        wildcard=config.DEFAULT_WILDCARD,
        indent=config.DEFAULT_INDENT,
        indent_headers=config.INDENT_HEADERS,
        wrap_curly_brace=config.WRAP_CURLY_BRACE,
        use_named_variables=config.DEFAULT_NAMED_VARIABLES,
        show_template=config.DEFAULT_SHOW_TEMPLATE,
        oneliner=config.DEFAULT_ONELINER,
        context={'bv': bv},
    )

    for header, value in config.DEFAULT_META_FIELDS.items():
        rule.add_meta(header, value)

    existing = set()
    for i, entity in enumerate(entities, start=1):
        if str(entity) not in existing:
            rule.add_string(f'op{i}', entity)
            existing.add(str(entity))

    for condition in config.DEFAULT_CONDITIONS:
        rule.add_condition(condition)

    return rule


def rule_for_range(bv: BinaryView, start: int, end: int) -> RuleBuilder:
    name = f'{utils.get_file_name(bv)}_0x{start:08X}'
    entities = YaraExtractor(utils.RangeExtractor(bv, start, end))
    return generate_rule(bv, name=name, entities=list(entities))


def rule_for_strings(bv: BinaryView, refs: Iterable) -> RuleBuilder:
    strings = []
    for ref in refs:
        string = utils.make_string(bv, ref)
        if string is not None:
            strings.append(YaraExtractor([string]))

    name = f'{utils.get_file_name(bv)}_strings'
    return generate_rule(bv, name=name, entities=list(chain.from_iterable(strings)))


def rule_for_function(bv: BinaryView, function: Function) -> Optional[RuleBuilder]:
    extractor = utils.FunctionExtractor(
        bv, function, block_min_size=config.FUNCTION_BLOCK_MIN_SIZE)
    rule = generate_rule(bv, name=function.name, entities=list(YaraExtractor(extractor)))
    return None if rule.is_empty() else rule


def ruleset_for_functions(
        bv: BinaryView,
        functions: List[Function],
        task: Optional[BackgroundTaskThread] = None) -> Optional[RulesetBuilder]:
    """Build a ruleset, None if cancelled"""
    ruleset = RulesetBuilder()
    for i, function in enumerate(functions, start=1):
        if task is not None:
            if task.cancelled:
                return None
            task.progress = f'{PLUGIN_NAME}: processing function ({i}/{len(functions)})'

        try:
            rule = rule_for_function(bv, function)
            if rule is not None:
                ruleset.append(rule)
        except Exception as e:
            log_error(f'unexpected error in {function.name}: {e}\n{traceback.format_exc()}')

    return ruleset


# --- UI ---

def _ui_available() -> bool:
    try:
        import binaryninjaui  # noqa: F401
        return True
    except ImportError:
        return False


def on_main_thread(func):
    """Run the decorated function on the UI thread (Qt widgets live there)"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        def call():
            try:
                func(*args, **kwargs)
            except Exception as e:
                log_error(f'{e}\n{traceback.format_exc()}')

        if is_main_thread():
            call()
        else:
            execute_on_main_thread(call)
    return wrapper


@on_main_thread
def show_rule(rule):
    """Open the rule editor"""
    from .ui import show_window
    from .ui.windows import main_window
    show_window(YaraDialog(rule, parent=main_window()))


def run_task(title: str, work: Callable[[BackgroundTaskThread], object]):
    """Run ``work`` in a cancellable background task, show its rule(set) in the editor"""

    class Task(BackgroundTaskThread):
        def __init__(self):
            super().__init__(f'{PLUGIN_NAME}: {title}', True)

        def run(self):
            try:
                result = work(self)
            except Exception as e:
                log_error(f'{title} failed: {e}\n{traceback.format_exc()}')
                bn.show_message_box(
                    PLUGIN_NAME, f'{title} failed: {e}', icon=bn.MessageBoxIcon.ErrorIcon)
                return

            if self.cancelled or result is None:
                log_info(f'{title} cancelled')
                return
            show_rule(result)

    Task().start()


def _make_yara_dialog_class():
    from . import ui

    class YaraDialog(ui.ClosableDialog):
        def __init__(self, rule, parent=None):
            self.rule = rule

            self.wildcard_combo = ui.ComboBox(
                items=[(label, int(mask)) for label, mask in config.WILDCARD_MODES],
                default=int(config.DEFAULT_WILDCARD),
                on_change=self.handle_wildcard_change,
            )
            self.comments_checkbox = ui.Checkbox(
                label='Show comments',
                default=config.DEFAULT_SHOW_COMMENTS,
                on_click=self.handle_comments_checkbox_click,
            )
            self.oneliner_checkbox = ui.Checkbox(
                label='One-liner',
                default=config.DEFAULT_ONELINER,
                on_click=self.handle_oneliner_click,
            )
            self.comments_checkbox.setEnabled(not config.DEFAULT_ONELINER)
            self.use_named_variables_checkbox = ui.Checkbox(
                label='Named variables',
                default=config.DEFAULT_NAMED_VARIABLES,
                on_click=self.handle_named_variables_click,
            )
            self.show_template_checkbox = ui.Checkbox(
                label='Show Yara Rule Template',
                default=config.DEFAULT_SHOW_TEMPLATE,
                on_click=self.handle_show_template_click,
            )
            self.indent_edit_label = ui.Label('Indentation')
            self.indent_edit = ui.NumberInput(
                default=config.DEFAULT_INDENT,
                min_value=2,
                max_value=8,
                step=1,
                on_change=self.handle_indent_change,
            )
            self.text_edit = ui.YaraTextEdit(rule.build())
            self.copy_btn = ui.Button('Copy', self.handle_copy_click)

            super().__init__(
                title='YarMaker - Generated Yara Rule',
                width=900,
                top_left_items=[
                    self.wildcard_combo,
                    self.comments_checkbox,
                    self.oneliner_checkbox,
                    self.use_named_variables_checkbox,
                ],
                top_right_items=[self.indent_edit_label, self.indent_edit],
                body_items=[self.text_edit],
                bottom_left_items=[self.show_template_checkbox],
                bottom_right_items=[self.copy_btn],
                parent=parent,
            )

        def _rebuild_rule(self):
            try:
                content = self.rule.build()
            except Exception as e:
                content = f'// error while building the rule: {e}'
                log_error(traceback.format_exc())
            self.text_edit.set_content(content)

        def handle_wildcard_change(self):
            self.rule.wildcard = Wildcard(self.wildcard_combo.value())
            self._rebuild_rule()

        def handle_comments_checkbox_click(self):
            self.rule.show_comments = self.comments_checkbox.is_checked()
            self._rebuild_rule()

        def handle_oneliner_click(self):
            oneliner = self.oneliner_checkbox.is_checked()
            self.rule.oneliner = oneliner
            self.comments_checkbox.setEnabled(not oneliner)
            # comments are never shown in oneliner mode
            self.rule.show_comments = self.comments_checkbox.is_checked()
            self._rebuild_rule()

        def handle_named_variables_click(self):
            self.rule.use_named_variables = self.use_named_variables_checkbox.is_checked()
            self._rebuild_rule()

        def handle_show_template_click(self):
            self.rule.show_template = self.show_template_checkbox.is_checked()
            self._rebuild_rule()

        def handle_indent_change(self):
            self.rule.indent = self.indent_edit.value()
            self._rebuild_rule()

        def handle_copy_click(self):
            from .ui.qt import QtWidgets
            QtWidgets.QApplication.clipboard().setText(self.text_edit.toPlainText())

    return YaraDialog


class _LazyDialog(object):
    """Defer Qt imports until a dialog is needed (headless safe)"""
    _cls = None

    def __call__(self, *args, **kwargs):
        if _LazyDialog._cls is None:
            _LazyDialog._cls = _make_yara_dialog_class()
        return _LazyDialog._cls(*args, **kwargs)


YaraDialog = _LazyDialog()


# --- commands ---

def cmd_rule_from_selection(bv: BinaryView, address: int, length: int):
    """Disassembly / IL views: rule from the selected range (or current item)"""
    if length <= 1:
        start, end = utils.get_item_range(bv, address)
    else:
        start, end = address, address + length

    run_task(
        f'rule for 0x{start:x}-0x{end:x}',
        lambda task: rule_for_range(bv, start, end),
    )


@on_main_thread
def cmd_rule_from_strings(bv: BinaryView):
    """Counterpart of the IDA Strings window action"""
    from .ui import PickerDialog, show_window
    from .ui.windows import main_window

    refs = list(utils.iter_strings(bv))
    if not refs:
        bn.show_message_box(PLUGIN_NAME, 'No strings found in this binary.')
        return

    rows = []
    for ref in refs:
        try:
            value = ref.value
        except Exception:
            value = ''
        value = value.rstrip('\x00').replace('\r', '\\r').replace('\n', '\\n')
        rows.append((f'0x{ref.start:x}', str(ref.length), ref.type.name.replace('String', ''), value))

    def accept(selected):
        run_task('rule from strings', lambda task: rule_for_strings(bv, selected))

    show_window(PickerDialog(
        title='YarMaker - Select Strings',
        columns=['Address', 'Length', 'Type', 'String'],
        rows=rows,
        payloads=refs,
        on_accept=accept,
        numeric_columns=(0, 1),
        parent=main_window(),
    ))


@on_main_thread
def cmd_ruleset_from_functions(bv: BinaryView):
    """Counterpart of the IDA Functions window action"""
    from .ui import PickerDialog, show_window
    from .ui.windows import main_window

    functions = sorted(bv.functions, key=lambda f: f.start)
    if not functions:
        bn.show_message_box(PLUGIN_NAME, 'No functions found in this binary.')
        return

    rows = [
        (f.name, f'0x{f.start:x}', str(f.total_bytes), str(len(f.basic_blocks)))
        for f in functions
    ]

    def accept(selected):
        run_task(
            f'ruleset for {len(selected)} function(s)',
            lambda task: ruleset_for_functions(bv, selected, task),
        )

    show_window(PickerDialog(
        title='YarMaker - Select Functions',
        columns=['Function', 'Address', 'Size', 'Blocks'],
        rows=rows,
        payloads=functions,
        on_accept=accept,
        numeric_columns=(1, 2, 3),
        parent=main_window(),
    ))


def cmd_ruleset_for_function(bv: BinaryView, function: Function):
    run_task(
        f'ruleset for {function.name}',
        lambda task: ruleset_for_functions(bv, [function], task),
    )


def cmd_ruleset_for_all_functions(bv: BinaryView):
    """Counterpart of the IDA plugin run (Ctrl+Alt+Y): hunting ruleset"""
    def work(task):
        task.progress = f'{PLUGIN_NAME}: collecting functions'
        functions = list(utils.get_custom_functions(
            bv,
            min_size=config.FUNCTIONS_MIN_SIZE,
            prefix=config.FUNCTIONS_NAME_PREFIX,
            skip_matched_functions=config.FUNCTIONS_SKIP_MATCHED,
        ))
        return ruleset_for_functions(bv, functions, task)

    run_task('ruleset for all functions', work)


def _set_default_keybinding(name: str, key: str):
    """Plugin commands are UI actions named after the command; give them a
    default key binding (users can override it in the keybindings editor)"""
    if not key:
        return
    try:
        from binaryninjaui import UIAction
        from PySide6.QtGui import QKeySequence
        if not UIAction.isActionRegistered(name):
            UIAction.registerAction(name, QKeySequence(key))
    except Exception as e:
        bn.log_debug(f'[{PLUGIN_NAME}] cannot bind {key} to {name}: {e}')


_registered = False


def register():
    global _registered
    if _registered:
        return
    _registered = True

    PluginCommand.register_for_range(
        CMD_RULE,
        'Generate a YARA rule from the selected instructions, strings and bytes',
        cmd_rule_from_selection,
    )
    PluginCommand.register(
        CMD_STRINGS,
        'Select strings and generate a YARA rule from them',
        cmd_rule_from_strings,
    )
    PluginCommand.register(
        CMD_FUNCTIONS,
        'Select functions and generate a YARA ruleset (basic blocks and referenced data)',
        cmd_ruleset_from_functions,
    )
    PluginCommand.register_for_function(
        CMD_FUNCTION,
        'Generate a YARA ruleset for the current function (basic blocks and referenced data)',
        cmd_ruleset_for_function,
    )
    PluginCommand.register(
        CMD_ALL_FUNCTIONS,
        'Generate a hunting YARA ruleset for all non-library functions',
        cmd_ruleset_for_all_functions,
    )

    if _ui_available():
        _set_default_keybinding(CMD_RULE, config.HOTKEY_RULE)
        _set_default_keybinding(CMD_ALL_FUNCTIONS, config.HOTKEY_ALL_FUNCTIONS)

    log_info(f'loaded, hotkey - {config.HOTKEY_RULE}')
