import pytest
from app import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
    })
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

def test_app_starts(client):
    """Test that the application can start and serve the home page"""
    response = client.get("/")
    assert response.status_code in [200, 302]  # Might redirect or render depending on setup
