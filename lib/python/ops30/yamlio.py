"""YAML in and out for site.yaml and the files render writes.

The one module in lib that needs PyYAML (python3-yaml); it is imported
lazily, so the drill commands keep working on a host without it.

load() is SafeLoader with two changes: a key that appears twice in one
mapping is an error (PyYAML keeps the last one silently), and dates and
timestamps stay strings (otherwise 2026-10-14 comes back as a date object
and every caller has to know that).
"""


class YamlError(ValueError):
    pass


def _yaml():
    try:
        import yaml
    except ImportError:
        raise YamlError("PyYAML is not installed (apt install python3-yaml)") from None
    return yaml


_LOADER = None
_DUMPER = None


def _loader():
    global _LOADER
    if _LOADER:
        return _LOADER
    yaml = _yaml()

    class Loader(yaml.SafeLoader):
        pass

    Loader.yaml_implicit_resolvers = {
        k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
        for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def mapping(loader, node, deep=False):
        seen = set()
        for k, _ in node.value:
            key = loader.construct_object(k, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", k.start_mark)
            seen.add(key)
        return loader.construct_mapping(node, deep=deep)

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    _LOADER = Loader
    return Loader


def loads(text, name="<string>"):
    yaml = _yaml()
    try:
        return yaml.load(text, Loader=_loader())
    except yaml.YAMLError as e:
        raise YamlError(f"{name}: {e}") from None


def load(path):
    with open(path, encoding="utf-8") as f:
        return loads(f.read(), str(path))


def _dumper():
    global _DUMPER
    if _DUMPER:
        return _DUMPER
    yaml = _yaml()

    class Dumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    def text(dumper, s):
        style = "|" if "\n" in s else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)

    Dumper.add_representer(str, text)
    _DUMPER = Dumper
    return Dumper


def dumps(obj):
    """Block style, keys in insertion order, UTF-8 kept, no aliases: the
    same input gives the same bytes."""
    yaml = _yaml()
    return yaml.dump(obj, Dumper=_dumper(), sort_keys=False, allow_unicode=True,
                     default_flow_style=False, width=1000)
