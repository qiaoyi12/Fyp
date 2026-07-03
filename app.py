import os
from flask import Flask
from sqlalchemy import inspect, text
from dotenv import load_dotenv
from backend.src.database.db import db, bcrypt
from backend.src.routes.upload import upload_bp
from backend.src.routes.pages import pages_bp


load_dotenv()

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'frontend'),
    static_folder=os.path.join(os.path.dirname(__file__), 'frontend'),
    static_url_path='/frontend'
)

# Config
app.secret_key        = os.getenv('SECRET_KEY', 'session-secret-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['UPLOAD_FOLDER']   = os.getenv('UPLOAD_FOLDER', 'uploadCsvStorage')

# Init extensions
db.init_app(app)
bcrypt.init_app(app)

# Register blueprints
app.register_blueprint(pages_bp)
app.register_blueprint(upload_bp, url_prefix='/api')

# Create DB tables
with app.app_context():
    db.create_all()

    inspector = inspect(db.engine)
    if 'analysis_results' in inspector.get_table_names():
        columns = {column['name'] for column in inspector.get_columns('analysis_results')}
        if 'file_ids' not in columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE analysis_results ADD COLUMN file_ids TEXT"))

if __name__ == '__main__':
    app.run(debug=True)