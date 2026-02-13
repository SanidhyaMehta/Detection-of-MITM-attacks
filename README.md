# MITM Attack Detection System

A Machine Learning-based system for detecting Man-in-the-Middle (MITM) attacks by analyzing network packet characteristics in real-time.

## Features

-  **Real-time Packet Analysis**: Captures and analyzes network packets in real-time
-  **ML-Powered Detection**: Uses Logistic Regression model to classify packets as Normal or Malicious
-  **Feature Extraction**: Analyzes key packet features (Ports, TTL, Length, Flags)
-  **Batch Processing**: Supports batch analysis of captured packets
-  **Model Training**: Includes scripts for training and retraining the detection model

## Project Structure

```
MITM attack/
├── src/
│   ├── Detection/
│   │   └── realtimeDetection.py    # Real-time packet detection
│   ├── ML_Model/
│   │   └── Traning.py               # Model training script
│   └── Sniffing/
│       ├── InitialPackets.py        # Initial packet capture
│       ├── enhanced_packet.py       # Enhanced packet analysis
│       └── LabellingData.py         # Data labeling utility
├── models/
│   ├── mitm_detector.pkl            # Trained ML model
│   └── scaler.pkl                   # Feature scaler
├── utils/
│   ├── config.py                    # Configuration settings
│   └── logger.py                    # Logging utilities
├── datasets/                        # Training datasets
├── tests/                           # Unit tests
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

## Prerequisites

- Administrator/Root privileges (required for packet sniffing)
- Network interface access
- Windows/Linux/MacOS

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd "MITM attack"
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Network Interface

Edit `utils/config.py` and set your network interface:
- **Windows**: Use format like `r"\Device\NPF_{GUID}"`
- **Linux**: Use interface name like `"eth0"` or `"wlan0"`
- **MacOS**: Use interface name like `"en0"`

To find your network interface:
- **Windows**: Run `ipconfig` or use Wireshark
- **Linux**: Run `ifconfig` or `ip addr`
- **MacOS**: Run `ifconfig` or `networksetup -listallhardwareports`

## Usage

### Real-time Detection

Run the real-time packet detection system:

```bash
python src/Detection/realtimeDetection.py
```

### Model Training

1. Prepare your labeled dataset (`labeled_packet_data.csv`)
2. Train the model:

```bash
python src/ML_Model/Traning.py
```

3. Convert models to production format:

```bash
python convert_models.py
```

### Test Model Inference

Test the trained model with sample data:

```bash
python test_inference.py
```

### Packet Capture

Capture packets for analysis:

```bash
python src/Sniffing/enhanced_packet.py
```

## Configuration

Key configuration settings in `utils/config.py`:

- `DATASET_PATH`: Path to raw packet dataset
- `MODEL_PATH`: Path to trained ML model
- `PACKET_LIMIT`: Number of packets to capture per session
- `NETWORK_INTERFACE`: Network interface for packet capture (set via environment variable)

## Model Features

The model analyzes the following packet features:
- **Source Port**: Source port number
- **Destination Port**: Destination port number
- **TTL (Time To Live)**: Packet TTL value
- **Length**: Packet length in bytes
- **Flags**: IP flags (DF, MF, etc.)

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Code Structure

- `src/Detection/`: Real-time detection modules
- `src/ML_Model/`: Machine learning training and inference
- `src/Sniffing/`: Packet capture and preprocessing
- `utils/`: Configuration and utility functions

## Troubleshooting

### Permission Errors

- **Windows**: Run as Administrator

### Network Interface Not Found

- Verify interface name/ID in `utils/config.py`
- Use `ifconfig` or `ipconfig` to list available interfaces
- Ensure the interface is active

### Model Not Found

- Ensure models are trained: `python src/ML_Model/Traning.py`
- Run model conversion: `python convert_models.py`
- Verify model files exist in `models/` directory

## Future Enhancements

- [ ] Web-based dashboard
- [ ] REST API for remote detection
- [ ] Database integration for historical analysis
- [ ] Real-time alerts and notifications
- [ ] Docker containerization
- [ ] Cloud deployment support


