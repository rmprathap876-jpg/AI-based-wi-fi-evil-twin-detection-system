This project focuses on detecting Wi-Fi Evil Twin attacks, where attackers create fake access points that mimic legitimate networks to steal user data. 
The system uses Machine Learning techniques to automatically classify Wi-Fi access points as Legitimate or Evil Twin based on network behavior and signal characteristics.
The project extracts features such as RSSI (signal strength), RSSI variance, beacon interval, channel number, beacon count, and frame count, and trains multiple ML models including Logistic Regression, SVM, Random Forest, and Gradient Boosting. 
The best-performing model is selected using metrics like Accuracy, Precision, Recall, F1-Score, and ROC-AUC.
The system supports both synthetic dataset generation and real-time Wi-Fi scanning, making it suitable for academic use as well as future real-world deployment in network security monitoring.
