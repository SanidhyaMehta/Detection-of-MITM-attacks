import sys
import subprocess
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QMessageBox, QTableWidget, QTableWidgetItem, QHBoxLayout, QFrame, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal


# Base directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

ENHANCED_PACKET_SCRIPT = os.path.join(BASE_DIR, "src", "Sniffing", "enhanced_packet.py")
LABELLING_SCRIPT = os.path.join(BASE_DIR, "src", "Sniffing", "LabellingData.py")
TRAINING_SCRIPT = os.path.join(BASE_DIR, "src", "ML_Model", "Traning.py")
REALTIME_DETECTION_SCRIPT = os.path.join(BASE_DIR, "src", "Detection", "realtimeDetection.py")


class DetectionThread(QThread):
    output_received = pyqtSignal(str)

    def run(self):
        process = subprocess.Popen(
            ["python3", REALTIME_DETECTION_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        for line in process.stdout:
            self.output_received.emit(line.strip())
        process.stdout.close()
        process.wait()


class MITMDetectionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('AI-based MITM Detection')
        self.setGeometry(200, 100, 800, 600)

        layout = QVBoxLayout()
        layout.setSpacing(10)

        self.greeting = QLabel('<h2>Welcome to the MITM Detection System</h2>', self)
        self.greeting.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.greeting)

        # Buttons
        button_layout = QHBoxLayout()
        self.train_new_button = QPushButton('Train New Model')
        self.train_new_button.clicked.connect(self.train_new_model)
        button_layout.addWidget(self.train_new_button)

        self.use_default_button = QPushButton('Start Detection with Default Model')
        self.use_default_button.clicked.connect(self.start_detection)
        button_layout.addWidget(self.use_default_button)
        layout.addLayout(button_layout)

        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        layout.addWidget(divider)

        # Table for displaying packet predictions
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "Source Port", "Destination Port", "TTL", "Length", "Flags", "Prediction"
        ])
        self.packet_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.packet_table.setStyleSheet("""
            QHeaderView::section { background-color: #444; color: white; padding: 4px; }
            QTableWidget { background-color: #1e1e1e; color: white; font-family: Consolas; font-size: 13px; }
        """)

        # Make columns equally spaced and responsive
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)

        layout.addWidget(self.packet_table)

        self.setLayout(layout)

    def train_new_model(self):
        try:
            QMessageBox.information(self, 'Training', 'Capturing packets and labeling dataset...')
            subprocess.run(["python3", ENHANCED_PACKET_SCRIPT], check=True)
            subprocess.run(["python3", LABELLING_SCRIPT], check=True)

            QMessageBox.information(self, 'Training', 'Training model on new data...')
            subprocess.run(["python3", TRAINING_SCRIPT], check=True)

            QMessageBox.information(self, 'Success', 'New model trained and saved successfully.')
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, 'Error', f"❌ An error occurred: {str(e)}")

    def start_detection(self):
        try:
            self.packet_table.setRowCount(0)
            QMessageBox.information(self, 'Detection', 'Real-time MITM detection started.')

            self.detection_thread = DetectionThread()
            self.detection_thread.output_received.connect(self.add_detection_row)
            self.detection_thread.start()

        except Exception as e:
            QMessageBox.critical(self, 'Error', f"❌ Detection failed: {str(e)}")

    def add_detection_row(self, line):
        if "Prediction:" in line and "Features:" in line:
            try:
                prediction_part = line.split("Prediction: ")[1].split(" |")[0]
                features_part = line.split("Features: ")[1].strip("[]")

                features = [f.strip() for f in features_part.split(",")]
                prediction = prediction_part

                row_position = self.packet_table.rowCount()
                self.packet_table.insertRow(row_position)

                for col, feature in enumerate(features):
                    item = QTableWidgetItem(feature)
                    self.packet_table.setItem(row_position, col, item)

                pred_item = QTableWidgetItem(prediction)
                pred_item.setTextAlignment(Qt.AlignCenter)

                if "Malicious" in prediction:
                    pred_item.setBackground(Qt.red)
                    pred_item.setForeground(Qt.white)
                elif "Normal" in prediction:
                    pred_item.setBackground(Qt.green)
                    pred_item.setForeground(Qt.black)

                self.packet_table.setItem(row_position, 5, pred_item)
                self.packet_table.scrollToBottom()

            except Exception as e:
                print("Line skipped due to parsing error:", e)
        else:
            print(line)  # Optional: show unrelated lines in terminal


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MITMDetectionApp()
    window.show()
    sys.exit(app.exec_())