# OpenThread Coding Conventions and Style

- [1 Python](#python)
  - [1.1 Standards](#standards)
  - [1.2 Conventions and Best Practices](#conventions-and-best-practices)
  - [1.3 Format and Style](#format-and-style)

# Python

## Standards

- OpenThread uses and enfores both Python 2 and Python 3. Support for Python 2 is a result of the fact that some current Linux distributions and Macs are still using 2.x as default.

## Conventions and Best Practices

- Run `pylint` over your code. `pylint` is a tool for finding bugs and style problems in Python source code. It finds problems that are typically caught by a compiler for less dynamic languages like C and C++. Because of the dynamic nature of Python, some warnings may be incorrect; however, spurious warnings should be fairly infrequent.

## Format and Style

- All code should adhere to [PEP 8](https://www.python.org/dev/peps/pep-0008/).
