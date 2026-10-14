"""30ops install: put a rendered site on the collector (collector.py) or a
node (node.py), idempotently. docs/install.md is the reference.

Every step looks at the host first and acts only on a difference, so a
second run reports no change; that is what the tests and the VM check
assert. Host access goes through ops.Ops, which tests replace.
"""
