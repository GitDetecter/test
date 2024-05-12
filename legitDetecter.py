from flask import Flask, request
from legitDeteterEvents import getEvent

# create a Flask app
app = Flask(__name__)

# define a route for webhook
@app.route('/webhook', methods=['POST'])
def webhook():
    if request.method == 'POST':
        event_type = request.headers.get('X-GitHub-Event')
        data = request.get_json()
        # get event object
        event = getEvent(event_type, data)
        # handle post request
        event.handle()
    # indicate that the delivery was successfully received
    return '', 202


# Define a route for homepage
@app.route('/')
def home():
    return "Welcome to legitDetecter"


if __name__ == '__main__':
    # Run the app
    app.run()