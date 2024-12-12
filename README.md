# ZeroUnveil: Explainable Malware Detection and Classification System

## Overview
ZeroUnveil is an explainable malware detection and classification system built with Flask (backend) and HTML/CSS/JavaScript (frontend). The system enables users to upload executable files for analysis, providing both binary detection (Malicious/Benign) and multi-class classification of malware. It also offers interpretability using LIME (Local Interpretable Model-Agnostic Explanations) to help users understand the features influencing classification decisions.

---

## Features

- **User Management**:
  - User registration, login, and profile management.
  - Password recovery and profile picture updates.
- **Malware Detection and Classification**:
  - Binary classification: Malicious or Benign.
  - Multi-class classification of malware types (e.g., Ramnit, Obfuscator.ACY).
- **Explainability**:
  - Generate textual LIME explanations for predictions.
  - Visualize LIME results in an interactive format.
- **Dynamic Dashboard**:
  - Displays recent scans, scan reports, and malware statistics.
  - Supports file uploads and live analysis.
- **Loader Animation**:
  - Displays a loader while results are being processed.
- **Responsive Design**:
  - Optimized for desktop and mobile devices.

---

## Technologies Used

### Frontend
- HTML, CSS, JavaScript
- Responsive UI with modern design elements

### Backend
- Flask
- Python

### Machine Learning
- Scikit-learn for SVM and Random Forest classifiers
- LIME for interpretability

### Additional Libraries
- Capstone for opcode extraction
- PEfile for portable executable file parsing
- Matplotlib and SHAP for visualizations

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Node.js and npm (optional for advanced frontend development)
- Virtual environment setup (recommended)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up the Environment**:
   - Ensure the `svm_model.joblib` and `random_forest_model.pkl` files are in the root directory.
   - Place `functions.csv` and any other necessary datasets in the correct directories.

4. **Run the Application**:
   ```bash
   python app.py
   ```

5. **Access the Application**:
   Open `http://127.0.0.1:5000/` in your browser.

---

## Usage

### File Upload and Analysis
1. Login or register an account.
2. Navigate to the **Scan** section on the dashboard.
3. Drag and drop or upload an executable file.
4. View binary detection and multi-class classification results.
5. Generate or visualize LIME explanations.

### Reports and Statistics
- Recent scans and reports are accessible in the **Reports** section.
- View detailed scan history and malware statistics.

---

## Project Structure
```
├── app.py                # Main Flask application
├── utils.py              # Helper functions for analysis and classification
├── templates/            # HTML templates for frontend
├── static/
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript files
│   ├── images/           # Images and logos
├── uploads/              # Directory for uploaded files
├── users.json            # User data storage
├── svm_model.joblib      # SVM model file
├── random_forest_model.pkl # Random Forest model file
├── functions.csv         # Dataset of known functions for feature extraction
└── requirements.txt      # Python dependencies
```

---

## Key Components

### 1. `app.py`
- Routes for login, signup, file upload, and explanation generation.
- Handles user session management and rendering templates.

### 2. `utils.py`
- Implements binary and multi-class prediction using SVM and Random Forest models.
- Extracts opcodes, byte entropy, and features from files.
- Provides LIME explanations for predictions.

### 3. Frontend
- `dashboard.html`: Main user dashboard with file upload and result visualization.
- `script.js`: Handles dynamic interactions like button clicks, file uploads, and scroll behavior.
- `style.css`: Defines responsive and visually appealing styles.

---

## Features in Detail

### 1. Binary Detection
- Classifies files as `Malicious` or `Benign` using pre-trained models.

### 2. Multi-Class Classification
- Further categorizes malicious files into specific malware families.

### 3. LIME Explanation
- Generates text and visual explanations for interpretability.

---

## Future Improvements
- Add support for additional file types.
- Integrate advanced visualization tools for LIME.
- Implement role-based access control for administrators.

---

## Contributing

Contributions are welcome! Please fork the repository and create a pull request for any feature additions or bug fixes.

---

## License
This project is licensed under the MIT License.

---

## Contact
For inquiries, please contact [your_email@example.com].
