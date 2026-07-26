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

# ─── FED: Analyst Agent ───────────────────────────────────────────────────────
from backend.src.routes.analyst import analyst_bp
app.register_blueprint(analyst_bp)

# Create DB tables
with app.app_context():
    db.create_all()

    inspector = inspect(db.engine)
    if 'analysis_results' in inspector.get_table_names():
        columns = {column['name'] for column in inspector.get_columns('analysis_results')}
        if 'file_ids' not in columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE analysis_results ADD COLUMN file_ids TEXT"))

    if 'alerts' in inspector.get_table_names():
        alert_columns = {column['name'] for column in inspector.get_columns('alerts')}
        with db.engine.begin() as connection:
            if 'assigned_analyst_id' not in alert_columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN assigned_analyst_id INTEGER"))
            if 'assignment_source' not in alert_columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN assignment_source VARCHAR(20)"))
            if 'assignment_reason' not in alert_columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN assignment_reason TEXT"))
            if 'assigned_at' not in alert_columns:
                connection.execute(text("ALTER TABLE alerts ADD COLUMN assigned_at DATETIME"))

    if 'analysis_assignments' in inspector.get_table_names():
        assignment_columns = {column['name'] for column in inspector.get_columns('analysis_assignments')}
        if 'manager_id' not in assignment_columns:
            with db.engine.begin() as connection:
                connection.execute(text("ALTER TABLE analysis_assignments ADD COLUMN manager_id INTEGER"))
                
        # separate check: analyst_id may still be NOT NULL from an older schema
        # version, even after the manager_id column was added above. SQLite can't
        # alter a column's constraint directly, so the whole table must be rebuilt.
        assignment_columns_info = inspector.get_columns('analysis_assignments')
        analyst_id_col = next((c for c in assignment_columns_info if c['name'] == 'analyst_id'), None)
        if analyst_id_col is not None and not analyst_id_col['nullable']:
            with db.engine.begin() as connection:
                connection.execute(text("""
                    CREATE TABLE analysis_assignments_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id INTEGER NOT NULL REFERENCES analysis_results(id),
                        analyst_id INTEGER REFERENCES users(id),
                        manager_id INTEGER REFERENCES users(id),
                        assigned_by INTEGER NOT NULL REFERENCES users(id),
                        assigned_at DATETIME
                    )
                """))
                connection.execute(text("""
                    INSERT INTO analysis_assignments_new
                        (id, analysis_id, analyst_id, manager_id, assigned_by, assigned_at)
                    SELECT id, analysis_id, analyst_id, manager_id, assigned_by, assigned_at
                    FROM analysis_assignments
                """))
                connection.execute(text("DROP TABLE analysis_assignments"))
                connection.execute(text(
                    "ALTER TABLE analysis_assignments_new RENAME TO analysis_assignments"
                ))

if __name__ == '__main__':
    app.run(debug=True)