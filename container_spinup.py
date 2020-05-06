"""
Container Spinup
Spin up a test container and artifact
Slack messages you the container id
"""

import phantom.rules as phantom
import sys
import json
import requests
import ipaddress

SLACK_USERS = ["@eshiau"]

def on_start(container):
    response_types = [
        {'prompt': 'Confirmation', 'options': {'type': 'list', 'choices': ["yes", "no"]}},
        {'prompt': 'Slack Username e.g. @user', 'options': {'type': 'message'}}]
    message = "Generating test container..."
    phantom.prompt2(message=message, container=container, user="Administrator", response_types=response_types, callback=create_container, respond_in_mins=100, trace=True)
    return

def create_container(action, success, container, results, handle):
    logger("results:{}action:{}", clean=True, comment=True, args=[results, action])

    for action_run in results:
        results_data = results[0]["action_results"][0]["data"]
        logger("results_data:{}".format(results_data), clean=True, comment=True)
        slack_user = results_data[0]["response"]
        logger("slack_user:{}".format(slack_user), clean=True, comment=True)

    sys.exit(1)
    cef = {}
    success, message, container_id = phantom.create_container(name='Testing Container',
                                                              label='test',
                                                              container_type='default')
    cef.update({
        "ContainerName": "1051: Rubix Lowtrust Suspicious Process Execution - cwd: /home/testing cmdline: [/usr/bin/curl -k 10.0.0.1:8081] was executed by [1001] on [i-lava-rubix]",
        "process_path": "/usr/bin",
        "user_id": "1001",
        "sourceHostName": "i-0b68b35dba9b2071a-bastion.eu-west-1a.production-lowtrust.lava-rubix",
        "destinationUserId": "1001",
        "process_name": "curl",
        "cmdline": "curl -k 10.0.0.1:8081",
        "host": "i-lava-rubix",
        "_originating_search": "https://sp-searchhead-014f79df1eff7038f:8000/app/search/search?latest=1588718721&q=%7C+savedsearch+%221051_Jail_Suspicious_Process_Execution_Rubix%22",
        "RID": "1051",
        "group_id": "3001",
        "cwd": "/home/testing",
        "rid": "1051",
        "sourceUsername": slack_user,
        "HumanPrompt": "This is a HumanPrompt"
    })
    success, message, artifact_id = phantom.add_artifact(container=container_id, raw_data={}, cef_data=cef, label="event", name="1051", severity="low", identifier=None, artifact_type="event")
    if success:
        logger("ENRICHMENT ARTIFACT ADDED - {} id: {}", debug=True, comment=True, args=[message, artifact_id], clean=False)


def on_finish(container, summary):
    logger('on_finish() called')
    resolve_container(container=container)
    return


def resolve_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    logger('resolve_container() called')

    # Closing out the container
    phantom.set_severity(container, "low")
    my_add_tags(tags=["automation"])
    # Updating required fields
    resolution_data = {"Resolution": "Trivial True Positive"}
    custom_fields = {"custom_fields": resolution_data}
    phantom.update(container, custom_fields)
    phantom.set_status(container, "closed")
    return


def logger(content, args=[], debug=True, comment=False, clean=False):
    if content:
        if debug:
            debugger(content, args=args, clean=clean)
        if comment:
            commenter(content, args=args, clean=clean)
    return


def debugger(content, phantom=phantom, args=[], clean=False):
    if args:
        debug_count = content.count("{}")
        var_count = len(args)
        if clean:
            content = "DEBUG:\n{}".format(content.replace("{}", ":\n{}\n"))
        else:
            content = "DEBUG: {}".format(content)
        if debug_count > var_count:
            diff = debug_count - var_count
            for i in range(diff):
                args.append("\nWARNING: More args than {}")
        if var_count > debug_count:
            phantom.debug("WARNING: More variables provided than {} placeholders")
        phantom.debug(content.format(*tuple(args)))
    else:
        phantom.debug("DEBUG: {}".format(content))
    return


def commenter(content, phantom=phantom, args=[], clean=False):
    if args:
        comment_count = content.count("{}")
        var_count = len(args)
        if clean:
            content = "automation: {}".format(content.replace("{}", ":\n{}\n"))
        if comment_count > var_count:
            diff = comment_count - var_count
            for i in range(diff):
                args.append("\nWARNING: More args than {}")
        if var_count > comment_count:
            phantom.comment(comment="WARNING: More variables provided than {} placeholders")
        phantom.comment(comment=content.format(*tuple(args)))
    else:
        phantom.comment(comment="automation: {}".format(content))
    return


def my_add_artifact(container=None, cef_dict=None, severity="low", label="enrichment", name="ENRICHMENT DATA", artifact_type="enrichment"):
    phantom.set_status(container, "open")
    if isinstance(cef_dict, dict):
        cef_json = flatten(phantom.collect2(container=container, datapath=["artifact:*.cef"]))[0]
        logger("PRE cef_json{}", debug=True, clean=True, args=[cef_json])
        if isinstance(cef_json, dict):
            cef_json.update(cef_dict)
            logger("POST cef_json{}", debug=True, clean=True, args=[cef_json])
            success, message, artifact_id = phantom.add_artifact(container=container, raw_data=cef_json, cef_data=cef_json, label=label, name=name, severity=severity, identifier=None, artifact_type=artifact_type)
            if success:
                logger("ENRICHMENT ARTIFACT ADDED - {} id: {}", debug=True, comment=True, args=[message, artifact_id], clean=False)
            else:
                logger("FAILURE: adding artifact\ncef_dict{}message{}", debug=True, comment=True, args=[cef_dict, message], clean=True)
    else:
        logger("FAILURE - cannot add non-dictionary to artifact\ncef_dict{}", debug=True, comment=True, args=[cef_dict], clean=True)
    return


def flatten(list_of_lists):
    try:
        list_in_lists = isinstance(list_of_lists[0], list)
    except IndexError as e:
        list_in_lists = False
    if list_in_lists:
        return [item for sublist in list_of_lists for item in sublist]
    else:
        return list_of_lists


def dedup(l):
    cleanObj = set(l)
    return list(cleanObj)


def custom_list_check(custom_list_name, arg):
    logger('phantom.check_list start')
    success, message, matched_row_count = phantom.check_list(list_name=custom_list_name, value=arg)
    debug = "phantom.check_list results: success:{}, message:{}, matched_row_count:{}"
    args = [success, message, matched_row_count]
    logger(debug, args=args)
    return success


def custom_list_add(custom_list_name, args):
    success, message = phantom.add_list(list_name=custom_list_name, values=args)
    debug = "phantom.check_list results: success:{}, message:{}"
    if success:
        logger("SUCCESS: '{}' added to list name: {}", args=[args, custom_list_name], clean=False)
    else:
        args = [success, message]
        logger("FAILURE: {} Message {}", args=args)
    return success


def my_save_data(key=None, value=None):
    if value is not None and key is not None:
        phantom.save_data(value, key=key)
        logger("key{}value{}", clean=True, args=[key, value])
    else:
        logger("phantom.save_data: Invalid Args{} {}", args=[key, value], comment=True)


def my_get_data(key, clear_data=False):
    if key is not None:
        return phantom.get_data(key=key, clear_data=clear_data)
    else:
        logger("phantom.get_data: Invalid Args{}", args=[key], comment=True)
        return None


def my_add_tags(tags, container=None, trace=True):
    success, message = phantom.add_tags(container=container, tags=tags, trace=trace)
    logger("Success{}Message{}", args=[success, message], clean=True)
    if success:
        logger("automation: Successfully tagged as: {}", args=[tags], comment=True)
    else:
        logger("ERROR: tagging failed {}", args=[tags], comment=True)


def my_get_tags(container=None, trace=True):
    success, message, tags = phantom.get_tags(container=container, trace=trace)
    logger("Success{}Message{}Tags{}", args=[success, message, tags], clean=True)
    if success:
        logger("GET Tags: {}", args=[tags], clean=True, comment=True, debug=False)
        return tags
    else:
        logger("ERROR: cannot get tags{}", args=[tags], clean=True, comment=True)