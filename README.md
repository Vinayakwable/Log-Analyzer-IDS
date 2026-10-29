🛡️ Log Analyzer and Intrusion Detection System (IDS)
A web-based cybersecurity project designed to analyze system authentication logs, detect suspicious login activities, and identify potential brute-force attacks.

📌 Project Overview
The **Log Analyzer and Intrusion Detection System (IDS)** is a cybersecurity application developed to help identify suspicious activities by analyzing system log files.
The application allows users to upload log files, analyze authentication events, and detect potentially malicious login attempts. It provides analysis results through a web interface to help users understand suspicious activities and possible security threats.
This project demonstrates the fundamentals of log analysis, intrusion detection, and security monitoring.

 🎯 Objectives

- Analyze system authentication logs.
- Detect multiple failed login attempts.
- Identify suspicious login activities.
- Recognize potential brute-force attacks.
- Display analysis results through a web interface.
- Improve understanding of security monitoring and incident detection.

✨ Key Features

- **Log File Upload:** Upload log files for security analysis.
- **Authentication Log Analysis:** Analyze Linux authentication logs, such as `auth.log`.
- **Brute-Force Detection:** Identify patterns of repeated failed login attempts.
- **Suspicious Activity Detection:** Highlight potentially malicious authentication behavior.
- **Web-Based Interface:** Interact with the application through a user-friendly dashboard.
- **Analysis Results:** Display detection results and relevant log information.
- **Cybersecurity Awareness:** Demonstrate how log analysis can support threat detection and investigation.

🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend logic and log analysis |
| Flask | Web application framework |
| HTML | Web page structure |
| CSS | Interface styling |
| JavaScript | Frontend interactions, if implemented |
| Linux Authentication Logs | Log data for security analysis |
| Git & GitHub | Version control and project hosting |

⚙️ How It Works

1. **Upload Logs:** The user uploads a supported authentication log file.
2. **Read Log Data:** The application reads and processes the uploaded log entries.
3. **Analyze Events:** The system examines authentication events for suspicious patterns.
4. **Detect Threats:** Repeated failed login attempts and other implemented detection rules are evaluated.
5. **Display Results:** The application presents the analysis results on the web interface.
6. **Investigate Findings:** The user reviews suspicious events to understand potential security incidents.

📂 Project Structure


Log-Analyzer-and-IDS/
│
├── app.py                  # Flask application and routes
├── config.py               # Application configuration
├── templates/              # HTML templates
├── static/                 # CSS, JavaScript, and other assets
├── requirements.txt        # Python dependencies
├── .gitignore              # Files excluded from Git
└── README.md               # Project documentation


 🚀 Installation and Setup
 Prerequisites

- Python 3.x
- pip
- Git (optional)
- A supported authentication log file for testing


🧪 Testing

The application can be tested using sample authentication logs containing different login scenarios.

| Test Scenario | Expected Purpose |
|---|---|
| Successful login | Check normal authentication events |
| Failed login | Verify failed-login analysis |
| Multiple failed logins | Test potential brute-force detection |
| Mixed login events | Evaluate analysis of different authentication outcomes |
| Suspicious authentication patterns | Check the detection rules implemented in the application |

Actual results depend on the log format and detection logic implemented in the project.

🔐 Security Considerations

- Use sample or sanitized log files during testing.
- Do not upload confidential production logs to an untrusted application.
- Validate uploaded files before processing.
- Restrict file types and file sizes.
- Avoid exposing sensitive information in analysis results.
- Run the application in a controlled environment when testing security scenarios.

🎓 Learning Outcomes

Through this project, I explored:

- Log analysis and authentication monitoring.
- Basic intrusion detection concepts.
- Identification of repeated failed login attempts.
- Python-based security automation.
- Flask web application development.
- Cybersecurity event analysis.
- Basic threat detection and investigation workflows.

 🔮 Future Enhancements

- Real-time log monitoring.
- IP address tracking and suspicious-source analysis.
- Configurable detection thresholds.
- Alert notifications for suspicious activities.
- Interactive dashboards and log statistics.
- Integration with SIEM platforms such as Splunk.
- Advanced detection rules and improved reporting.

👨‍💻 Author

**Vinayak Dattatray Wable**

Cybersecurity Enthusiast | Aspiring SOC Analyst

⚠️ Disclaimer

This project was developed for educational and cybersecurity learning purposes. Use it only with log files and systems you are authorized to access.

⭐ If you find this project useful, consider giving the repository a star.
