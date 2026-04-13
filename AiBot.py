from flask import Flask
from flask_cors import CORS

# Imports the model setup function that loads or creates
# the machine learning models used by the phishing detector
from model_utils import init_models

# Imports functions that connect the models to the route handlers
# and then attach all API routes to the Flask app
from routes import register_routes, init_route_models

# Creates the main Flask application
app = Flask(__name__)

# Enables Cross-Origin Resource Sharing so the frontend
# can send requests to this backend from a different origin
CORS(app)

# Loads and prepares the batch model and online learning model
batch_model, online_model = init_models()

# Passes the models into the route layer so the endpoints
# can use them when analysing text or saving feedback
init_route_models(batch_model, online_model)

# Registers all Flask routes such as /chat, /feedback, /metrics, and /health
register_routes(app)

# Starts the Flask server on port 5050
# debug=False is safer for final project use
# use_reloader=False prevents the app from starting twice
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)