# My Flask App

This is a simple Flask web application that demonstrates the basic structure and functionality of a Flask project.

## Project Structure

```
my-flask-app
├── app.py                # Main application file
├── requirements.txt      # Project dependencies
├── templates             # HTML templates
│   ├── index.html       # Main page template
│   └── layout.html      # Base layout template
├── static                # Static files
│   └── style.css        # CSS styles
└── README.md            # Project documentation
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd my-flask-app
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

To run the application, execute the following command:
```
python app.py
```

The application will be accessible at `http://127.0.0.1:5000/`.

## Usage

- Navigate to the main page to see the application in action.
- Modify the templates and styles as needed to customize the application.

## License

This project is licensed under the MIT License.