# User Guide

This guide will go through installation and basic configuration for Synapse.   

+ [Installation](#installation)
    + [Dependecies](#dependecies)
+ [Configuration](#configuration)
    + [Synapse user](#synapse-user)
    + [api section](#api-section)
    + [TheHive section](#thehive-section)
+ [Start the app](#start-the-app)
+ [Deployment to Production](#deployment-to-production)
    + [Instructions](#instructions)
    + [Stopping the application](#stopping-the-application)
    + [Starting the application](#starting-the-application)
    + [Logs](#logs)
+ [Update](#update)

## Installation

### Dependecies

```
sudo apt install python3-distutils
sudo apt install python3-pip
sudo apt install python3-dev libkrb5-dev gcc
sudo pip3 install -r requirements.txt
```

## Configuration

### Synapse user
Before filling in the configuration file, create a new user in TheHive for Synapse with the following details:

```
Login:                     synapse
Full name:                 synapse
Roles:                     read, write
Additional Permissions:    ✓ Allow alerts creation
```

And create an API Key.   

Now edit the configuration file located at ```Synapse/conf/synapse.conf```.

### [api] section

The ```[api]``` section is related to the flask API and log settings. You can keep it as it is for ```debug```, ```host```, ```threaded``` value. You may want to change the default port ```5000``` and set ```dockerized``` to true if you are running Synapse in a docker container. This will print the logging to stdout instead of the log file.

#### Example

```
api:
  debug_mode: false
  host: 0.0.0.0
  port: 5000
  threaded: true
  log_level: INFO
  dockerized: false
```

### Automation section
The automation section is related to (surprise, surprise...) the automation related functionality. Here you can enable/disable it entirely, or make sure it is tailored to your needs by adjusting the file path for the configuration files, start time fields used in the description for alerts and cases and more.

```
Automation:
  enabled: false
  enable_customer_list: false
  automation_config_dir: /path/to/automation_config
  event_start_time: Start Time
  #event start time related to your environment. Elastic: "%Y-%m-%dT%H:%M:%S.%fZ" QRadar: "%Y-%m-%d %H:%M:%S"
  event_start_time_format: "%Y-%m-%dT%H:%M:%S.%fZ"
  internal_contact: <customer_id>
  debug_contact: <customer_id>
  automation_regexes: 
    - 'uc-\w+-\d{3}\w{0,2}'
```

### Modules section

In this section, put in configuration values required for each module. More information can ben found in the corresponding module guide

#### Example

```
TheHive:
  url: http://127.0.0.1:9000
  user: synapse
  api_key: r4n0O8SvEll/VZdOD8r0hZneOWfOmth6
```

Basic configuration for Synapse is done.   
To configure workflows, head to the [workflows page](workflows/README.md).

## Start the app

To start Synapse, run:

```
python3 app.py
```

## Deployment to Production

If you'd like to go live with Synapse, it is advised to use a WSGI server.
The below will show you how to deploy Synapse as a service with gunicorn and supervisor but feel free to use any others tools for your deployment.

This part is mainly taken from the excellent [Flask Mega Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xvii-deployment-on-linux-even-on-the-raspberry-pi) by Miguel Grinberg. 
Have a look at the section named "Setting Up Gunicorn and Supervisor" for the "original" deployment instructions.

### Instructions

 * Download the WSGI server and the process control system:

```
sudo apt-get install gunicorn3
sudo apt-get install supervisor
```

 * Create the user ```synapse```, this user is dedicated to running the application.

```
sudo adduser --disabled-login synapse
```

 * Create ```/etc/supervisor/conf.d/synapse.conf``` as follow:

```
[program:synapse]
command=/usr/bin/gunicorn3 -b 0.0.0.0:5000 -w 4 app:app
directory=/opt/Synapse
user=synapse
environment=REQUESTS_CA_BUNDLE="<PATH_TO_EWS_CERT>"
autostart=true
autorestart=true
stopasgroup=true
killasgroup=true
```

In this case, Synapse is located at ```/opt/Synapse``` as indicated by ```directory=/opt/Synapse```.
Feel free to adapt ```directory``` to your context.   
Just make sure that user ```synapse``` has enough rights on this directory:

```
sudo chown -R synapse:synapse /opt/Synapse/
```

**Make also sure to replace ```<PATH_TO_EWS_CERT>``` with the file path to your ews certificate.**

 * Reload supervisor to make the changes effective:

```
sudo supervisorctl reload
```

From here the application should be deployed and running on port 5000.
It also means that your server has now port 5000 **open**.

### Stopping the application

To stop Synapse, run:

```
sudo supervisorctl stop synapse
```

### Starting the application

To start Synapse, run:

```
sudo supervisorctl start synapse
```

### Logs

Logs for supervisor are located under:

```
/var/log/supervisor/
```

Regarding Synapse, if the application is located at ```/opt``` then logs are under:

```
/opt/Synapse/logs/
```

# Update

In order to update Synapse (minor version), just pull the new version from Github and run the application:

```
cd Synapse/
git pull
```
