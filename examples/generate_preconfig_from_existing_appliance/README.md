# Generate Preconfig YAML from Existing EdgeConnect Appliance

![Python](https://img.shields.io/badge/Python-3.12.2-green)

This is a Python-based project developed using the **pyedgeconnect** library that pulls data
from an existing HPE Aruba EdgeConnect appliance and builds, validates, and deploys a preconfig
YAML configuration to the Orchestrator.

---

## Table of Contents

1. [Project Status](#project-status)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [License](#license)

---

## Project Status

🚧 **Under Development** 🚧

- This project is currently a work in progress. Features may be incomplete or subject to change.

---

## Features

- **Pyegeconnect**: Uses the `pyedgeconnect` library to interact with APIs.
- **Templating**: Implements templating using `Jinja2` to generate output dynamically.
- **Environment Variables** Uses the `python-dotenv` library to utilize local environment variables.
- **Python 3.12.2**: Leverages the latest features in Python 3.12.2. Earlier versions of Python3 may work fine.

---

## Installation

To run this project locally, follow these steps:

### 1. Clone the Repository
Clone the repository using Git:
```bash
git clone https://github.hpe.com/adam-wilkins/PreconfigYAMLFromExistingAppliance.git
cd <repo-name>
```

### 2. Set up a Virtual Environment
Set up and activate your virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate       # On macOS/Linux
venv\Scripts\activate          # On Windows
```

### 3. Install Dependencies
Install the required packages:

*Please note the development branch of Pyedgeconnect is currently required for this to function.
The correct path for the development branch of Pyedgeconnect is indicated in the requirements.txt file.*

```bash
pip install -r requirements.txt
```
---

### 4. Create .env file in root of directory with Environment Variables
Read the ".env_example-README" file in this repository's root directory.

## Usage

Follow the instructions below to use the project:

1. **Edit the main.py script**
   - Edit the nePK ID value in the DeploymentInfo("--nePK_ID--") for the device you want to generate a preconfig
   - If you want to have the script upload the YAML file to Orchestrator, set **upload_to_orch=True**
   
2. **Run the Script**  
   Execute the main script with:
   ```bash
   python main.py
   ```

3. **Features Overview**  
   - The script interacts with a multitude of Orchestrator REST API endpoints using the **pyedgeconnect** library to retrieve data from an EdgeConnect appliances (sometimes multiple) to generate a Preconfig YAML file that can be used against existing or new EdgeConnect appliances.
   - The script will also validate and push the preconfig YAML file to the Orchestrator for operator/engineer use.

4. **Output**
   - Once you run the project, the output (a preconfig YAML file) will appear in the "preconfig_outputs" directory.

---

## License

This project is licensed under the [MIT License](LICENSE). You are free to use and modify it for personal and commercial purposes.

---
