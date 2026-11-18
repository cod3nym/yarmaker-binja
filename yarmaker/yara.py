from collections import UserList
import inspect
import re
from typing import Any, Dict, List, Union, Optional, Iterable, Callable
import textwrap

from .types import Wildcard, DEFAULT_WILDCARD
from .wrappers import YaraEntity


class RuleBuilder(object):
    def __init__(
            self, 
            name: str,
            show_comments: bool = True,
            wildcard: Wildcard = DEFAULT_WILDCARD,
            indent: int = 3,
            indent_headers: bool = True,
            wrap_curly_brace: bool = False,
            use_named_variables: bool = True,
            show_template: bool = True,
            oneliner: bool = False,
            context: Optional[Dict[str, Any]] = None,
        ):
        self.name = self._escape_name(name)
        # values passed by name to meta/condition callables (e.g. 'bv')
        self.context: Dict[str, Any] = dict(context or {})

        self.show_comments = show_comments
        self.wildcard = wildcard
        self.indent = indent
        self.indent_headers = indent_headers
        self.wrap_curly_brace = wrap_curly_brace
        self.use_named_variables = use_named_variables
        self.show_template = show_template
        self.oneliner = oneliner

        self.meta: Dict[str, Union[str, Callable]] = {}
        self.strings: Dict[str, YaraEntity] = {}
        self.conditions: List[Union[str, Callable]] = []

    def _escape_name(self, name) -> str:
        _name = ''.join(x if x.isalnum() else '_' for x in name)
        _name = _name.replace('__', '_')

        # hack for 80 symbols limit
        if len(_name) >= 80:
            _name = _name[:38] + '__' + _name[-38:]

        return _name

    def add_meta(self, name: str, value: Union[str, Callable]):
        if not any((isinstance(value, str), callable(value))):
            raise TypeError('Meta value must be str or callable object')

        if callable(value):
            unknown = set(inspect.signature(value).parameters) - set(self.context)
            if unknown:
                raise TypeError(
                    f'Callable meta value can only take {sorted(self.context)} arguments')

        self.meta[name] = value
        return self

    def add_string(self, name, value: YaraEntity):
        self.strings[name] = value
        return self

    def add_condition(self, condition: Union[str, Callable]):
        if not any((isinstance(condition, str), callable(condition))):
            raise TypeError('Condition must be str or callable object')

        if callable(condition):
            params = list(inspect.signature(condition).parameters)
            known = set(self.context) | {'count'}
            if not (len(params) <= 1 or set(params) <= known):
                raise TypeError(
                    f'Callable condition can take {sorted(known)} arguments '
                    'or a single strings count argument')

        self.conditions.append(condition)
        return self

    def build(self):
        if not self.show_template:
            return self.build_strings(with_header=False)

        sanitized_name = self.sanitize_rule_name(self.name)
        result = f"rule {sanitized_name}"
        result += '\n' if self.wrap_curly_brace else ' '
        result += '{\n'

        content = ''
        content += self.build_meta()
        content += self.build_strings()
        content += self.build_condition()
        
        result += self._indent(content) if self.indent_headers else content
        result += "}\n"
        return result

    def build_meta(self):
        result = "meta:\n"
        for key, value in self.meta.items():
            _value = self._call(value) if callable(value) else value
            result += self._indent(f'{key} = "{_value}"')
            result += '\n'
        result += "\n"
        return result

    def build_strings(self, with_header: bool = True):
        result = "strings:\n" if with_header else ''
        for key, value in self.strings.items():
            content = value.build(
                show_comments=self.show_comments,
                wildcard=self.wildcard,
                indent=self.indent,
                oneliner=self.oneliner,
            )
            var_name = key if self.use_named_variables else ''
            line = f'${var_name} = {content}'
            result += self._indent(line) if with_header else line
            result += '\n'
        if with_header:
            result += "\n"
        return result

    def build_condition(self) -> str:
        result = "condition:\n"
        total = []
        for value in self.conditions:
            if callable(value):
                _value = self._call(value, count=len(self.strings))
            else:
                _value = value

            if _value:
                total.append(str(_value))

        result += '\nand '.join(total)
        result += '\n'

        return self._indent(result).lstrip()

    def _call(self, func: Callable, **extra) -> Any:
        """Call a meta/condition callable, passing arguments by name.

        Known names are the rule context (e.g. 'bv') and 'count' (strings
        count). A single argument with another name gets the strings count
        (compatible with ``lambda count: ...`` of the IDA version)
        """
        values = {**self.context, **extra}
        params = list(inspect.signature(func).parameters)
        if len(params) == 1 and params[0] not in values:
            return func(extra.get('count', len(self.strings)))
        return func(**{name: values[name] for name in params})

    def is_empty(self) -> bool:
        return len(self.strings) == 0

    @classmethod
    def is_rule_name_valid(cls, name: str) -> bool:
        return cls.sanitize_rule_name(name) == name

    @staticmethod
    def sanitize_rule_name(name: str) -> str:
        name = re.sub(r'[^0-9a-zA-Z_]+', '_', name)

        # check name starts with any digit
        if re.match(r'^\d', name):             
            name = f'_{name}'

        if len(name) <= 3:
            raise ValueError(f'Sanitized rule name "{name}" less than 3 chars')
        return name

    def _indent(self, value: str) -> str:
        prefix = ' ' * self.indent
        return textwrap.indent(value, prefix=prefix)

    def _build_entity(self, entity: YaraEntity) -> str:
        content = entity.build(
            show_comments=self.show_comments,
            wildcard=self.wildcard,
            indent=self.indent,
            oneliner=self.oneliner,
        )

        return content


RULE_OPTIONS = frozenset({
    'show_comments', 'wildcard', 'indent', 'indent_headers',
    'show_template', 'oneliner', 'use_named_variables',
})


class RulesetBuilder(UserList):
    def __init__(self, rules: Optional[Iterable[RuleBuilder]] = None):
        if not rules:
            rules = list()

        super().__init__(rules)

    def build(self) -> str:
        rules = [rule.build() for rule in iter(self)]
        if not rules:
            return '// no rules generated (nothing matched the filters)\n'

        return '\n\n'.join(rules)

    def __setattr__(self, name: str, value: Any):
        if name in RULE_OPTIONS:
            for rule in iter(self):
                setattr(rule, name, value)
        else:
            super().__setattr__(name, value)
