"""
Playbook Template
"""

# Import necessary python libraries
import phantom.rules as phantom
import json
import sys
import time
import helper_phantom as helper
from datetime import datetime, timedelta



### Global Variables ####
SLACK_DESTINATIONS = ["#infosec-cirt-alerts"]


"""
on_start() is a phantom function that tells the playbook where to begin
"""
def on_start(container):
    helper.my_logger(content="on_start() called container id: {}", args=[container['id']], comment=True)
    # Collects data from the container; returns as list of lists
    artifact_collection = phantom.collect2(container=container, datapath=["artifact:*.cef.SlackGroupName"])
    # return a single list
    clean_artifact = helper.flatten(artifact_collection)
    # return the single string
    slack_destination = clean_artifact[0]

    # necessary parameters for the slack phantom app; each app has respective parameters required
    parameters = []
    parameters.append({
        'destination': slack_destination,
        'message': "",
    })
    """
    The callback parameter is the name of the function that will run directly after this phantom action finishes. 
    This is a phantom special and used to chain functions after using 'phantom.act()'
    """
    phantom.act("send message", parameters=parameters, assets=['slackbot'], callback=resolve_container, name="send_intro_message")
    return

"""
Resolve Container
1. Sets severity to Low
2. Resolution: Trivial True Positive
3. Adds "automation" tag
3. Closes container
"""
def resolve_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('resolve_container() called')

    # Closing out the container
    phantom.set_severity(container, "low")
    my_add_tags(tags=["automation"])
    # Updating required fields
    resolution_data = {"Resolution": "Trivial True Positive"}
    custom_fields = {"custom_fields": resolution_data}
    phantom.update(container, custom_fields)
    phantom.set_status(container, "closed")
    return


def my_add_tags(container=None, tags=None, trace=True):
    success, message = phantom.add_tags(container=container, tags=tags, trace=trace)
    helper.my_logger(content="Success{}Message{}", args=[success, message], clean=True)

"""
on_finish() is a phantom function that tells the playbook where to end after all other functions run
"""
def on_finish(container, summary):
    helper.my_logger(content='on_finish() called')
    return
