"""A Python-based API for Using Renderbus cloud rendering service."""

# pylint: disable=import-error
# Import third-party modules
from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    # Package is not installed.
    __version__ = '1.4.0'
