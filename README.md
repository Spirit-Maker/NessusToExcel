# NessusToExcel
Parse Nessus XML report to generate excel report with necessary information.

# Project Name

Brief description or purpose of your project.

## Getting Started

These instructions will help you set up the project on your local machine.

### Prerequisites

- Python (version 3.10.x)

### Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Spirit-Maker/NessusToExcel.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd NessusToExcel
    ```

3. **Create a virtual environment:**

    ```bash
    # On Unix or MacOS
    python3 -m venv venv

    # On Windows
    python -m venv venv
    ```

4. **Activate the virtual environment:**

    ```bash
    # On Unix or MacOS
    source venv/bin/activate

    # On Windows
    .\venv\Scripts\activate
    ```

    You should see the virtual environment's name in your command prompt.

5. **Install project dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

    This will install all the required packages listed in the `requirements.txt` file.

6. **Run the project:**

    ```bash
    python3 nessus_report_maker.py

    # Further select options for folders and scans. You can select multiple scans in a folder by scan_id comma separated e.g. 12,34,123
    ```

    

7. **Deactivate the virtual environment:**

    ```bash
    deactivate
    ```


## License

This project is licensed under the [GNU3] - see the [LICENSE.md](LICENSE.md) file for details.



