import pytest
from flask import Flask
from routes import register_routes, init_route_models

class DummyBatchModel:
    def predict_proba(self, texts):
        return [[0.2, 0.8]]

class DummyOnlineModel:
    _fitted = True
    _sample_count = 25

    def predict_proba_one(self, text):
        return 0.7

    def update(self, X, y):
        pass

    def rebuild_from_all_data(self):
        pass

    def save(self):
        pass

@pytest.fixture
def client():
    app = Flask(__name__)
    init_route_models(DummyBatchModel(), DummyOnlineModel())
    register_routes(app)
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client