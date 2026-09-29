"""
M1 — Парсер C-AST (libclang). Разбирает целевую функцию в AST и извлекает
последовательность вызовов известных арифметических примитивов
(dilithium_mul/invntt/add/sub/poly_red/vec_check_low и т.п.) в порядке
исходного кода — это то, что M2 использует для построения графа границ.

Не делает полный символьный анализ выражений (вне scope MVP v0) — извлекает
call-граф в пределах функции/диапазона строк, с именами аргументов там, где
это простые идентификаторы.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import clang.cindex as cindex


@dataclass
class CallSite:
    """Один вызов функции, найденный в AST, с позицией в исходнике."""
    callee: str
    line: int
    args: list[str] = field(default_factory=list)


@dataclass
class FunctionTrace:
    name: str
    start_line: int
    end_line: int
    calls: list[CallSite]


def _arg_names(call_node: cindex.Cursor) -> list[str]:
    names = []
    for child in call_node.get_arguments():
        text = "".join(t.spelling for t in child.get_tokens())
        names.append(text if text else child.spelling or "?")
    return names


def _find_function(cursor: cindex.Cursor, func_name: str):
    for child in cursor.walk_preorder():
        if (child.kind == cindex.CursorKind.FUNCTION_DECL
                and child.spelling == func_name
                and child.is_definition()):
            return child
    return None


def parse_function_calls(file_path: str, func_name: str, args: list[str] | None = None) -> FunctionTrace:
    """Парсит file_path через libclang, находит определение func_name,
    возвращает последовательность вызовов функций внутри её тела в порядке
    появления в исходнике."""
    index = cindex.Index.create()
    parse_args = args or ["-std=c99"]
    tu = index.parse(file_path, args=parse_args)

    func_node = _find_function(tu.cursor, func_name)
    if func_node is None:
        raise ValueError(f"Функция {func_name!r} не найдена (как definition) в {file_path}")

    extent = func_node.extent
    calls: list[CallSite] = []
    for node in func_node.walk_preorder():
        if node.kind == cindex.CursorKind.CALL_EXPR:
            callee = node.spelling
            if not callee:
                continue
            calls.append(CallSite(
                callee=callee,
                line=node.location.line,
                args=_arg_names(node),
            ))

    return FunctionTrace(
        name=func_name,
        start_line=extent.start.line,
        end_line=extent.end.line,
        calls=calls,
    )


def filter_calls_by_line_range(trace: FunctionTrace, start: int, end: int) -> list[CallSite]:
    return [c for c in trace.calls if start <= c.line <= end]
