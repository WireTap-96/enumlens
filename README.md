# EnumLens

An offline parser that turns a saved Nmap XML report from an owned lab or explicitly authorized assessment into a compact JSON inventory of hosts and open services. EnumLens does **not** run Nmap, send packets, or connect to any host.

## Requirements and use

Python 3.9+; standard library only.

```bash
python -m enumlens.cli sample-lab.xml
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Scope and limitations

- Parses only local XML input; output is a summary, not a vulnerability assessment.
- Use scan data only when the original assessment was explicitly authorized and within scope.
- Reports may contain sensitive system details. Sanitize before sharing or committing real results.
- Initial starter implementation created with AI assistance; review and extend it before representing the work as your own.
