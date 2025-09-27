import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import config

# Create Flask application
app = Flask(__name__)

# Configuration using centralized config.py
app.config.update({
    'SECRET_KEY': os.environ.get('SECRET_KEY', config.SECRET_KEY),
    'UPLOAD_FOLDER': config.UPLOAD_FOLDER,
    'MAX_CONTENT_LENGTH': config.MAX_CONTENT_LENGTH,
    'SQLALCHEMY_DATABASE_URI': config.ORACLE_DATABASE_URL,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_ENGINE_OPTIONS': config.ORACLE_ENGINE_OPTIONS
})

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Faça login para acessar esta página.'
login_manager.login_message_category = 'info'

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Make version available in all templates
@app.context_processor
def inject_version():
    return {
        'VERSION': config.VERSION,
        'APP_NAME': config.APP_NAME,
        'APP_FULL_NAME': config.APP_FULL_NAME
    }

# Custom Jinja2 filter to convert newlines to <br> tags (similar to PHP's nl2br)
@app.template_filter('nl2br')
def nl2br_filter(text):
    """Convert newlines to HTML line breaks"""
    if text is None:
        return ''
    return text.replace('\n', '<br>').replace('\r\n', '<br>').replace('\r', '<br>')

# Configure logging
import logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Initialize database
with app.app_context():
    try:
        import models
        db.create_all()
        app.logger.info("Tabelas do banco de dados verificadas/criadas com sucesso!")
    except Exception as e:
        app.logger.warning(f"Aviso ao verificar tabelas: {e}")