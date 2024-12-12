import os
import pefile
import numpy as np
import pandas as pd
import joblib
from groq import Groq



# Load the trained model and functions only once
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, 'svm_model.joblib')
functions_path = os.path.join(current_dir, 'functions.csv')

if not os.path.isfile(model_path):
    raise FileNotFoundError(f"Model file not found: {model_path}")

rf_model = joblib.load(model_path)

if not os.path.isfile(functions_path):
    raise FileNotFoundError(f"Functions file not found: {functions_path}")

all_functions_df = pd.read_csv(functions_path)
all_functions = all_functions_df['function'].tolist()

def extract_imports(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = {}
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            function_names = []
            for imp in entry.imports:
                if imp.name:
                    function_names.append(imp.name.decode('utf-8'))
            imports[dll_name] = function_names
        return imports
    except Exception as e:
        raise ValueError(f"Error extracting imports: {e}")

def calculate_byte_entropy(file_path):
    try:
        with open(file_path, 'rb') as file:
            byte_arr = np.frombuffer(file.read(), dtype=np.uint8)
        byte_freq = np.bincount(byte_arr, minlength=256)
        byte_prob = byte_freq / np.sum(byte_freq)
        entropy = -np.sum(byte_prob * np.log2(byte_prob + 1e-10))  # Adding small value to avoid log(0)
        return byte_freq, entropy
    except Exception as e:
        raise ValueError(f"Error calculating byte entropy: {e}")

def process_features(imports, entropy, all_functions):
    try:
        import_features = {func: 0 for func in all_functions}
        for dll, funcs in imports.items():
            for func in funcs:
                if func in import_features:
                    import_features[func] = 1
        import_features_list = list(import_features.values())
        features = np.array([entropy] + import_features_list)
        return features
    except Exception as e:
        raise ValueError(f"Error processing features: {e}")

def predict(file_path):
    try:
        imports = extract_imports(file_path)
        _, entropy = calculate_byte_entropy(file_path)
        features = process_features(imports, entropy, all_functions).reshape(1, -1)
        prediction = rf_model.predict(features)[0]
        return 'Malicious' if prediction == 1 else 'Benign'
    except Exception as e:
        return f"Error: {e}"

#MULTICLASS

import collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from lime.lime_tabular import LimeTabularExplainer
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import shap

# Directories for saving plots
UPLOAD_FOLDER = 'uploads/'
STATIC_FOLDER = 'static/'

class_mapping = {
    1: 'Ramnit',
    2: 'Lollipop',
    3: 'Kelihos_ver3',
    4: 'Vundo',
    5: 'Simda',
    6: 'Tracur',
    7: 'Kelihos_ver1',
    8: 'Obfuscator.ACY',
    9: 'Gatak'
}

# Load the pre-trained RandomForest model
model = joblib.load('random_forest_model.pkl')

# Load the scaler used during training
scaler = StandardScaler()

# Opcodes to track
OPCODES = ['call', 'jmp', 'mov', 'add', 'sub', 'inc', 'dec', 'ret']

# Ensure the directories exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if not os.path.exists(STATIC_FOLDER):
    os.makedirs(STATIC_FOLDER)

# Function to extract assembly and count opcodes using Capstone
def extract_and_count_opcodes(file_path):
    with open(file_path, 'rb') as f:
        code = f.read()

    # Initialize Capstone disassembler for x86 64-bit architecture (adjust if needed)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    opcode_counts = collections.Counter({opcode: 0 for opcode in OPCODES})

    # Disassemble the binary and count occurrences of the specified opcodes
    total_opcodes = 0
    for i in md.disasm(code, 0x1000):
        if i.mnemonic in OPCODES:
            opcode_counts[i.mnemonic] += 1
            total_opcodes += 1

    # Add the total opcode count as a feature
    opcode_counts['total_opcodes'] = total_opcodes

    return opcode_counts

# Function to map the prediction to the corresponding malware class
def map_prediction_to_class(prediction):
    return class_mapping.get(prediction, "Unknown Class")


# Redefine STATIC_FOLDER here
#STATIC_FOLDER = 'static'

# Helper function for LIME explainability
def explain_with_lime(model, features, data_row, feature_names, scaler):
    # Ensure the features are scaled and normalized
    scaled_features = scaler.transform(features)  # Scale the input features

    # Initialize the LIME explainer with discretization turned off for continuous features
    explainer = LimeTabularExplainer(
        scaled_features, 
        mode='classification', 
        feature_names=feature_names, 
        class_names=[class_mapping[i] for i in sorted(class_mapping.keys())],  # Use class names from your class_mapping
        discretize_continuous=False
    )

    # Get the prediction probabilities
    scaled_sample = scaler.transform([data_row])  # Scale the data row before prediction
    prediction_probabilities = model.predict_proba(scaled_sample)
    
    # Find the index of the class with the highest probability
    predicted_class_idx = prediction_probabilities.argmax()

    # Print the prediction probabilities and the selected class
    print(f"Prediction probabilities: {prediction_probabilities}")
    print(f"Explaining class with highest probability: {class_mapping[predicted_class_idx + 1]}")

    # Get the explanation for the specific data_row
    explanation = explainer.explain_instance(
        scaled_sample[0],  # The sample to explain
        model.predict_proba,  # The model's predict_proba function
        num_features=len(feature_names),  # Number of features to show in the explanation
        labels=(predicted_class_idx,)  # Focus on the class with the highest probability
    )

    # Optionally save the explanation as an HTML file for interactive use
    explanation.save_to_file(os.path.join(STATIC_FOLDER, 'lime_explanation_sample.html'))

    print(f"LIME explanation saved as HTML at: {os.path.join(STATIC_FOLDER, 'lime_explanation_sample.html')}")

    # Extract and format the explanation
    explanation_text = format_lime_explanation(explanation)
    '''print(explanation_text)'''

    client = Groq(api_key="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")
    completion = client.chat.completions.create(
        model="llama3-8b-8192",
        messages=[
            {
                "role": "system",
                "content": "You are an assistant trained to explain machine learning model predictions. A file has been analyzed, classified as malicious, and further categorized into specific malware types using multi-class classification. A LIME analysis was conducted to understand the influence of certain features on this classification. Please provide a clear explanation based on the following feature impacts."
            },
            {
                "role": "user",
                "content": explanation_text
            }
        ],
        temperature=1,
        max_tokens=520,
        top_p=1,
        stream=True,
        stop=None,
    )

    '''for chunk in completion:
        print(chunk.choices[0].delta.content or "", end="")'''

    return explanation_text,completion





# Main function to run the model and explainability
def predict_multiclass(file_path):
    
    try:
        # Extract opcodes from the provided .exe file
        opcode_counts = extract_and_count_opcodes(file_path)

        # Convert the opcode features to a DataFrame (model expects tabular data)
        feature_order = ['total_opcodes', 'call', 'jmp', 'mov', 'add', 'sub', 'inc', 'dec', 'ret']
        opcode_counts = {feature: opcode_counts.get(feature, 0) for feature in feature_order}
        X = pd.DataFrame([opcode_counts])

        # Check if training data exists
        training_data_path = 'merged_features_labels.csv'
        if not os.path.exists(training_data_path):
            print(f"Training data not found at {training_data_path}. Please provide the correct path.")
            return
        
        # Fit the scaler using the training data
        training_data = pd.read_csv(training_data_path)  # Replace with your actual data path
        training_features = training_data.drop(columns=['filename', 'Class'])
        scaler.fit(training_features)

        # Make predictions using the loaded model
        predictions = model.predict(scaler.transform(X))  # Scale X before passing to the model
        mapped_prediction = map_prediction_to_class(predictions[0]+ 1)
        return mapped_prediction
    except Exception as e:
        return f"Error: {e}"
    


# Define a function to format the LIME explanation into a text summary
def format_lime_explanation(exp):
    exp_list = exp.as_list(label=exp.available_labels()[0])
    feature_effects = []
    for feature, weight in exp_list:
        # Determine the direction of the effect
        direction = "positive" if weight > 0 else "negative"
        feature_effects.append(f"{feature} had a {direction} effect with a weight of {weight:.2f}")
    
    # Join all features into a single description
    explanation_text = ". ".join(feature_effects)
    return explanation_text






