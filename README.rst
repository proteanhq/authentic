========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - |
        |
    * - package
      - | |version| |wheel| |supported-versions| |supported-implementations|
        | |commits-since|

.. |docs| image:: https://readthedocs.org/projects/authentic/badge/?style=flat
    :target: https://readthedocs.org/projects/authentic
    :alt: Documentation Status

.. |version| image:: https://img.shields.io/pypi/v/authentic.svg
    :alt: PyPI Package latest release
    :target: https://pypi.python.org/pypi/authentic

.. |commits-since| image:: https://img.shields.io/github/commits-since/proteanhq/authentic/v0.0.1.svg
    :alt: Commits since latest release
    :target: https://github.com/proteanhq/authentic/compare/v0.0.1...master

.. |wheel| image:: https://img.shields.io/pypi/wheel/authentic.svg
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/authentic

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/authentic.svg
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/authentic

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/authentic.svg
    :alt: Supported implementations
    :target: https://pypi.python.org/pypi/authentic


.. end-badges

Comprehensive Authentication Package

* Free software: BSD 3-Clause License

Installation
============

::

    pip install authentic

Documentation
=============

https://authentic.readthedocs.io/

Development
===========

To run the all tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
