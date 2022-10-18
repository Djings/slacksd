import logging
logging.basicConfig(level=logging.DEBUG)

import sys
import string
import json
import re
import threading
import os
import glob
import time
import random
from queue import Queue, Empty
from slack_sdk.web import WebClient
from slack_sdk.socket_mode import SocketModeClient
import subprocess as sp

# Initialize SocketModeClient with an app-level token + WebClient
client = SocketModeClient(
    # This app-level token will be used only for establishing a connection
    app_token=os.environ.get("SLACKSD_APP_TOKEN"),  # xapp-A111-222-xyz
    # You will be using this WebClient for performing Web API calls in listeners
    web_client=WebClient(token=os.environ.get("SLACKSD_BOT_TOKEN"))  # xoxb-111-222-xyz
)

stable_diffusion_promt = os.environ.get("SLACKSD_STABLE_DIFFUSION_PROMPT")

required_env = ["SLACKSD_STABLE_DIFFUSION_PROMPT", "SLACKSD_APP_TOKEN", "SLACKSD_BOT_TOKEN"]
for e in required_env:
  if os.environ.get(e) is None:
    print("Environment variable", e, "required but not set")
    sys.exit(1)

from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.request import SocketModeRequest

logger = logging.getLogger("SlackSD")

message_queue = Queue()

def parse_rich_text_to_plain_text(rich_text):
  result_text = ""

  # go over all elements
  for s in rich_text["elements"]:
    if s["type"] == "rich_text_section":
      for e in s["elements"]:
        if e["type"] == "text":
          result_text = result_text + e["text"]

  return result_text


def sanatize_prompt(prompt):
  allowed = string.ascii_letters + '"!()[];:-.,/_ ' + string.digits
  prompt = ''.join(filter(lambda x: x in allowed, prompt.encode('ASCII', "ignore").decode('ASCII')))

  forbidden_strings = [" -o", " --out"]
  for p in forbidden_strings:
    if p in prompt:
      return ""

  return prompt.strip()

def parse_prompt_text_from_event(event):
  text = ""
  blocks = event["blocks"]
  for b in blocks:
    if b["type"] == "plain_text":
      text = text + b["type"]["text"]
    elif b["type"] == "rich_text":
      text = text + parse_rich_text_to_plain_text(b)

  return sanatize_prompt(text)


def parse_non_threadded_message(client: SocketModeClient, event, userid):
  msg_ts = event["ts"]
  thread_ts = event["ts"]
  if "thread_ts" in event:
    thread_ts = event["thread_ts"]
  in_thread = msg_ts != thread_ts
  channel_id = event["channel"]

  logger.debug("parse event: " + repr(event))
  prompt = parse_prompt_text_from_event(event)
  logger.debug(f" process parsed and sanatize prompt: {prompt}")

  if len(prompt) < 3:
    client.web_client.reactions_add(name="rage", channel=channel_id, timestamp=thread_ts)
    blocks = list()
    blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : f"*Error prompt too short (min. 3 chars required)*"}})
    blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : f"*Prompt:* {prompt}"}})
    client.web_client.chat_postMessage(channel=channel_id, thread_ts=thread_ts, blocks=blocks)
    return

  msg = {"prompt": prompt, "channel" : channel_id, "ts" : thread_ts, "userid" : userid }
  message_queue.put(json.dumps(msg))


def parse_mention(client: SocketModeClient, payload):
    event = payload["event"]
    userid = event["user"]
    msg_ts = event["ts"]
    thread_ts = event.get("thread_ts", event.get("ts"))
    in_thread = msg_ts != thread_ts

    channel_id = event["channel"]

    client.web_client.reactions_add(name="eyes", channel=event["channel"], timestamp=event["ts"])

    if not in_thread:
      parse_non_threadded_message(client, event, userid)


def split_blocks(long_string, prefix="", postfix=""):
  lines = long_string.splitlines()
  blocks = list()
  collect = ""
  while len(lines) > 0:
    collect = collect + lines.pop(0) + "\n"
    if len(collect) > 2500:
      stdout_str = f"{prefix}{collect}{postfix}"
      blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : stdout_str}})
      collect = ""

  if len(collect) > 0:
    stdout_str = f"{prefix}{collect}{postfix}"
    blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : stdout_str}})

  return blocks


def remove_args(args, args_to_remove):
  # e.g. args_to_remove = ["n", "U"]
  olist = args.split("-")

  new_args = []
  for o in olist:
    ok = True
    for p in args_to_remove:
      if o.startswith(p):
        ok = False
    if ok:
      n = o
      if len(o) > 0 and not o.endswith(' '):
        n = n + " "

      new_args.append(n)

  return new_args

def process(client: SocketModeClient, req: SocketModeRequest):
  logger.debug("Request type: {req.type}")

  if req.type == "interactive":
    response = SocketModeResponse(envelope_id=req.envelope_id)
    client.send_socket_mode_response(response)
    payload = req.payload
    userid = payload["user"]["id"]

    actions = payload["actions"]
    task = actions[0]["action_id"]
    value_str = actions[0]["value"]
    base = json.loads(value_str)
    channel_id = payload["channel"]["id"]
    message = payload["message"]
    thread_ts = message.get("thread_ts", message.get("ts"))

    if task.startswith("similar"):
      logger.debug("Variations based on: {base}")
      args = base["args"]
      new_args = remove_args(args, ["v", "n"])
      v = task[7:]
      if len(v.strip()) == 0:
        v = ".1"
      new_args.append(f"v{v}")

      prompt = base["prompt"] + " " + "-".join(new_args)
      msg = {"prompt": prompt, "channel" : channel_id, "ts" : thread_ts }
      msg["userid"] = userid
      message_queue.put(json.dumps(msg))
    elif task == "upscale2":
      logger.debug("Upscale based on: {base}")
      args = base["args"]
      new_args = remove_args(args, ["n", "U"])
      new_args.append("U 2")
      prompt = base["prompt"] + " " + "-".join(new_args)
      msg = {"prompt": prompt, "channel" : channel_id, "ts" : thread_ts, "in_thread" : True}
      msg["userid"] = userid
      message_queue.put(json.dumps(msg))
    elif task.startswith("redo"):
      v = task[4:]
      if len(v.strip()) == 0:
        v = 1

      logger.debug("Redo based on: {base}")
      args = base["args"]
      new_args = remove_args(args, ["n", "U", "S", "v", "V"])
      prompt = base["prompt"] + " " + "-".join(new_args)
      msg = {"prompt": prompt, "channel" : channel_id, "ts" : thread_ts}
      msg["userid"] = userid
      for x in range(v):
        message_queue.put(json.dumps(msg))


  if req.type == "events_api":
    # Acknowledge the request anyway
    response = SocketModeResponse(envelope_id=req.envelope_id)
    client.send_socket_mode_response(response)

    if req.payload["event"]["type"] == "app_mention":
      parse_mention(client, req.payload)




def process_slack_reply(client : SocketModeClient, message, raw_message):
  if "prompt" not in message:
    return


  if "state" in message and message["state"] == "running":
    ts = message["ts"]
    channel = message["channel"]
    client.web_client.reactions_add(
        name="lower_left_paintbrush",
        channel=channel,
        timestamp=ts,
    )
    return

  # state is "done"/"idle"
  # completed painting

  prompt = message["prompt"]
  args = message["args"]
  ts = message["ts"]
  channel = message["channel"]
  full_output = message["stdout"]
  in_thread = message.get("in_thread", False)
  userid = message.get("userid", "")

  # if there is no image in message, paining failed
  if "image" not in message:
    client.web_client.reactions_add(
        name="boom",
        channel=channel,
        timestamp=ts,
    )

    blocks = []
    if len(full_output) > 0:
      blocks = split_blocks(full_output, "```", "```")
    else:
      if "stderr" in message and len(message["stderr"]) > 0:
        blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : f"```" + message["stderr"] + "```"}})
      else:
        blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : f"```Unknown error occured```"}})

    client.web_client.chat_postMessage(
        channel=channel,
        thread_ts=ts,
        blocks=blocks,
    )
    return

  imagefile = message["image"]

  conversation = client.web_client.conversations_open(users=userid)
#{'ok': True, 'no_op': True, 'already_open': True, 'channel': {'id': 'D041BKAKSF9'}}

  dm_id = None
  if conversation["ok"]:
    dm_id = conversation["channel"]["id"]

  publish_to = [channel]
  if dm_id is not None:
    publish_to.append(dm_id)

  if not in_thread:
    # most cases reply in channel
    result = client.web_client.files_upload(
        channels=publish_to,
        file=imagefile,
        title=f"{prompt} {args}",
    )
  else:
    # upscale replies go to the thread
    result = client.web_client.files_upload(
        channels=publish_to,
        file=imagefile,
        title=f"{prompt} {args} by <@{userid}>",
        thread_ts=ts,
    )

  new_file = result['file']

  def do_shares(share_items):
    for chan, share in share_items.items():
      if chan == dm_id:
        continue

      for s in share:
        ts = ""
        if "ts" in s:
          ts = s["ts"]
        if "thread_ts" in s:
          ts = s["thread_ts"]

        client.web_client.chat_postMessage(
            channel=chan,
            thread_ts=ts,
            text=f"{prompt} {args}",
        )

        #blocks = list()
        #blocks.append({"type" : "section", "text" : { "type" : "mrkdwn", "text" : f"This work was comissioned by <@{userid}>"}})
        #client.web_client.chat_postMessage(
        #    channel=chan,
        #    thread_ts=ts,
        #    blocks=blocks,
        #)

        blocks = list()
        blocks.append({ "type" : "header", "text" : { "type" : "plain_text", "text" : "Create more based on this prompt" }})
        action_value = {"prompt" : prompt, "args" : args, "image" : imagefile}
        action_value_str = json.dumps(action_value)
        buttons = list()
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Very Similar" }, "action_id" : "similar.05", "value" : action_value_str})
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Similar" }, "action_id" : "similar.1", "value" : action_value_str})
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Somewhat Similar" }, "action_id" : "similar.25", "value" : action_value_str})
        blocks.append({ "type" : "actions", "elements" : buttons })
        buttons = list()
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Redo" }, "action_id" : "redo", "value" : action_value_str})
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Redo 5x" }, "action_id" : "redo5", "value" : action_value_str})
        blocks.append({ "type" : "actions", "elements" : buttons })
        buttons = list()
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "Upscale 2x" }, "action_id" : "upscale2", "value" : action_value_str})
        buttons.append({"type" : "button", "text" : { "type" : "plain_text", "text" : "SD 2x" }, "action_id" : "embiggen", "value" : action_value_str})
        blocks.append({ "type" : "actions", "elements" : buttons })

        client.web_client.chat_postMessage(
            channel=chan,
            thread_ts=ts,
            blocks=blocks,
        )

        if len(full_output) > 0:
          blocks = list()
          blocks = split_blocks(full_output, "```", "```")
          client.web_client.chat_postMessage(
              channel=chan,
              thread_ts=ts,
              blocks=blocks,
          )

  if "private" in new_file["shares"]:
    do_shares(new_file["shares"]["private"])

  if "public" in new_file["shares"]:
    do_shares(new_file["shares"]["public"])


# Add a new listener to receive messages from Slack
# You can add more listeners like this
client.socket_mode_request_listeners.append(process)
client.message_listeners.append(process_slack_reply)

# Establish a WebSocket connection to the Socket Mode servers
client.connect()

def sanatize_output(output):
  result = []
  # remove all paths exept for the last part
  for l in output.splitlines():
    clean_line = []
    for part in l.split(" "):
      if len(part) > 0 and part[-1] == ":" and os.path.exists(part[:-1]):
        clean_line.append(os.path.basename(part[:-1]) + ":")
      else:
        clean_line.append(part)
    result.append(" ".join(clean_line))

  return "\n".join(result)


def parse_output(out, clean_out):
  m = re.search(r'Outputs:\n(.*)goodbye!', out, re.DOTALL)
  if m is None:
    return []

  resultstr = m.group(1)
  result = []

  for l in resultstr.splitlines():
    if len(l.strip()) < 4:
      continue
    m = re.search(r'^\[[\d\.]+\] (.*): (.*)(".*") (.*)$', l)
    if m is not None:
      img, bang_cmd, prompt, args = m.groups()
      if len(bang_cmd.strip()) > 0:
        prompt = bang_cmd.strip() + " " + prompt
      result.append({"image" : img, "prompt" : prompt, "args" : args, "stdout" : clean_out })

  return result


# open a stable diffusion connection
class SDPuppeteer(threading.Thread):
    def __init__(self, logger):
      threading.Thread.__init__(self)
      self.logger = logger.getChild("Puppeteer")

    def run(self):
      state = "idle"
      process = None
      current_task = None
      output = ""
      error = ""

      while True:
        if state == "idle":
          try:
            msg_str = message_queue.get(timeout=1)
            msg = json.loads(msg_str)
            output = ""
            error = ""
            prompt = msg["prompt"]
            current_task = msg
            cmd = [stable_diffusion_promt]
            self.logger.debug("run sd process command " + repr(cmd))
            process = sp.Popen(cmd, stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
            try:
              out, err = process.communicate(input=prompt, timeout=1)
              output += out
              error += err
            except sp.TimeoutExpired:
              pass
            state = "running"
            current_task["state"] = state
            current_task["args"] = ""
            client.enqueue_message(json.dumps(current_task))
          except Empty:
            time.sleep(1)


        elif state == "running":
            try:
              out, err = process.communicate(timeout=1)
              output += out
              error += err
            except sp.TimeoutExpired:
              pass

            if process.returncode is not None:
              state = "idle"
              clean_output = sanatize_output(output)
              results = parse_output(output, clean_output)
              self.logger.debug("Results from SD: " + repr(results))
              current_task["state"] = state
              current_task["stderr"] = error
              if len(results) == 0:
                current_task["stdout"] = clean_output
                if "image" in current_task:
                  del current_task["image"]
                client.enqueue_message(json.dumps(current_task))
              for r in results:
                current_task.update(r)
                client.enqueue_message(json.dumps(current_task))


            else:
              self.logger.debug("processing " + repr(current_task))



puppeteer = SDPuppeteer(logger)
puppeteer.start()

threading.Event().wait()








