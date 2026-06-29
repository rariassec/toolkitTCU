
import importlib
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent

def _all_modules():
    mods = []
    for path in _ROOT.rglob("*.py"):
        if "__pycache__" in str(path) or path.parent.name == "tests":
            continue
        rel = path.relative_to(_ROOT.parent)
        if path.name == "__init__.py":
            dotted = str(rel.parent).replace("/", ".")
        else:
            dotted = str(rel.with_suffix("")).replace("/", ".")
        mods.append(dotted)
    return sorted(set(mods))

@pytest.mark.parametrize("module", _all_modules())
def test_modulo_importa(module):
    importlib.import_module(module)
