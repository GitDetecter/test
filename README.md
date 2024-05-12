# test
A command line application for detecting suspicious git behaviors

The application is consisted of two Python files:
1. Running file named legitDetecter.py - this file uses flask to run the application locally. It listens to requests sent to /webhook and handle the requests.
2. Events file named legitDetecterEvent.py - this file specifies the suspicious events and handle them. It contains a generic event class and a subclass for each event that should be checked.

To run the application, navigate in the command line to the folder containing these files and type "python legitDetecter.py".

The GitHub organization was configured such that webhook requests of three kinds are sent: 'push', 'team', 'repository'. The requests are sent to an online endpoint defined using ngrok and tunneled to local port.

In order to expand the application to handle more events, one can expand an existing event class with new methods or add event class, specify the new class in the 'getEvent' method in the second file and enable webhook request of that type in the organization Settings. 
