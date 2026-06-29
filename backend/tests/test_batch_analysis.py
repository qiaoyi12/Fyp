import csv
import os
import tempfile
import unittest

from app import app
from backend.src.database.db import db
from backend.src.database.models import UploadedFile
from backend.src.services import data_service


class BatchAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite:///:memory:', UPLOAD_FOLDER=tempfile.mkdtemp())
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _write_csv(self, path, rows):
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow([
                'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
                'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
                'Fwd IAT Mean', 'Bwd IAT Mean', 'Packet Length Mean', 'Packet Length Std',
                'Destination Port', 'Average Packet Size', 'Fwd Packet Length Mean',
                'Bwd Packet Length Mean', 'Fwd Packets/s', 'Bwd Packets/s',
                'SYN Flag Count', 'ACK Flag Count', 'PSH Flag Count',
                'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
            ])
            writer.writerows(rows)

    def test_run_analysis_accepts_multiple_uploads(self):
        with self.app.app_context():
            upload_a_path = os.path.join(self.app.config['UPLOAD_FOLDER'], 'a.csv')
            upload_b_path = os.path.join(self.app.config['UPLOAD_FOLDER'], 'b.csv')
            self._write_csv(upload_a_path, [[100, 2, 1, 10, 5, 1000, 10, 20, 1, 20, 1, 50, 2, 80, 50, 10, 5, 100, 50, 0, 1, 0, 100, 100]])
            self._write_csv(upload_b_path, [[200, 3, 2, 20, 10, 2000, 20, 30, 2, 30, 2, 60, 3, 443, 60, 20, 10, 200, 100, 0, 1, 1, 100, 100]])

            upload_a = UploadedFile(filename='a.csv', filepath=upload_a_path, row_count=1, is_valid=True, user_id=1)
            upload_b = UploadedFile(filename='b.csv', filepath=upload_b_path, row_count=1, is_valid=True, user_id=1)
            db.session.add_all([upload_a, upload_b])
            db.session.commit()

            record, error, metrics = data_service.run_analysis([upload_a.id, upload_b.id], 1)

            self.assertIsNone(error)
            self.assertIsNotNone(record)
            self.assertEqual(record.user_id, 1)
            self.assertGreaterEqual(record.total_rows, 0)


if __name__ == '__main__':
    unittest.main()
