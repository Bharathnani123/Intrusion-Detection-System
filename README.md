# Intrusion-Detection-System
🔐 Intrusion Detection System (IDS) Using Decision Tree

📌 Project Overview

This project is a Machine Learning-based Intrusion Detection System (IDS) that detects malicious network traffic using the KDD Cup 99 dataset. It uses a Decision Tree Classifier to classify network activity as either normal or an attack, and further identifies the specific type of attack. The IDS is deployed through a user-friendly Flask web application, allowing users to enter network parameters and get predictions in real-time.

🎯 Objectives

To build an effective Intrusion Detection System using supervised learning.

To classify network traffic as normal or attack.

To further identify the type of attack using multi-class classification.

To provide an intuitive web interface for real-time predictions.

To raise awareness of cybersecurity threats through the Assist page.

🧠 Machine Learning Model

Algorithm Used: Decision Tree Classifier

Dataset: KDD Cup 1999 Dataset

Features Selected (Top 8 for simplicity & accuracy):

duration, protocol_type, service, flag, src_bytes, dst_bytes, count, srv_count

Label: Network traffic type (e.g., normal, neptune, smurf, satan, etc.)

⚙️ How It Works

Data Preprocessing

Load and label columns from the dataset.

Encode categorical features like protocol_type, service, and flag.

Select the top 8 most impactful features.

Split the data into training and test sets.

Model Training

Train a DecisionTreeClassifier on the selected features.

Save the trained model using joblib.

Web Application (Flask)

Home page allows users to input network parameters.

Model predicts whether the input is normal or an attack.

Result is displayed with clear classification (e.g., "🚨 Attack Detected: SATAN").

Assist Page

Educates users about the dataset features and common attack types.

Describes how the system works and its importance in real-world scenarios.

🛠️ Technologies Used

Component Technology

Backend Model - Python (scikit-learn, pandas)

Web Framework - Flask

Frontend Styling - HTML, CSS

Model Serialization - Joblib

Dataset - KDD Cup 1999

🧪 Accuracy

Achieved accuracy of over 99% on the training and testing dataset using the Decision Tree Classifier.

Can be improved further by using ensemble models like Random Forest or deep learning techniques.

🚀 Future Scope

Real-time traffic monitoring with packet capture tools (e.g., Wireshark, Zeek).

Integration with cloud platforms for scalability.

Use of Deep Learning (e.g., CNN, RNN) for more accurate predictions.

Mobile app for remote monitoring.

Integration with SIEM platforms for enterprise security workflows.

Visual dashboards and auto-report generation.

About
No description, website, or topics provided.
Resources
 Readme
 Activity
Stars
 0 stars
Watchers
 0 watching
Forks
 0 forks
Report repository
Releases
No releases published
Packages
No packages published
Languages
HTML
69.3%
 
Python
30.7%
Footer
