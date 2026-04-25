"""Shared modules used by both the relay and UI services.

Both Docker images COPY this directory at build time so they can share
the same SQLAlchemy models, Fernet crypto helpers, archive writer and
retention constants without risking drift between services.
"""
