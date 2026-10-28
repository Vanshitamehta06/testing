"""Tests use a fresh in-memory database (set before the app is imported)."""
import os

os.environ.setdefault("DATABASE_PATH", ":memory:")
