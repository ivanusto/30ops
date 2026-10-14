"""Vendor adapters: how 30ops talks to one kind of device from one vendor.

The adapters themselves live in adapters/<kind>/<vendor>/ at the top of the
repository: adapter.yaml says what the adapter can do, adapter.py does it.
This package holds what they share: the kind contract (schema), metric
output (base), the ways of reaching a device (transport) and the loader
(registry). docs/adapters.md is the reference.
"""
