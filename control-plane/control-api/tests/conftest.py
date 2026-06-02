"""Test fixtures: a TestClient backed by an isolated in-memory SQLite DB."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import crud
from app.db import Base, get_db
from app.main import create_app
from common import default_locked_down_profile


@pytest.fixture
def client() -> Iterator[TestClient]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # one shared in-memory connection for the test
        future=True,
    )
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)
    Base.metadata.create_all(bind=engine)

    # Minimal seed: a superadmin and the deny-most default profile.
    seed_db = testing_session()
    crud.create_admin(seed_db, "admin", "admin", "superadmin")
    crud.create_profile(
        seed_db, default_locked_down_profile("default", profile_id="default-locked-down")
    )
    seed_db.close()

    def override_get_db() -> Iterator[Session]:
        db = testing_session()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.state.test_engine = engine  # exposed so tamper tests can corrupt a stored row
    with TestClient(app) as test_client:
        yield test_client
    engine.dispose()
