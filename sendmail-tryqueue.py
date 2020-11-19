#!/usr/bin/env python3
#
# sendmail-tryqueue.py by lenormf
# A generic utility that caches/queues emails that couldn't be sent
#

import os
import re
import sys
import shlex
import random
import logging
import pathlib
import argparse
import datetime
import subprocess
import email.parser
import email.policy


class Defaults:
    DIR_QUEUES = os.path.join(os.getenv("XDG_DATA_HOME") or
                              os.path.join(os.getenv("HOME"), ".local", "share"),
                              "sendmail-tryqueue", "queues")
    NAME_DEFAULT_QUEUE = "default"
    EXT_EML = ".eml"
    EXT_SH = ".sh"


class SendmailTryQueueError(Exception): pass


class SendmailTryQueueBase:
    def __init__(self, queue_directory, queue_name):
        self.queue_directory = queue_directory
        self.queue_name = queue_name

        try:
            self.queue_directory_max_path = os.pathconf(self.queue_directory,
                                                        "PC_PATH_MAX")
            self.queue_directory_name_len = os.pathconf(self.queue_directory,
                                                        "PC_NAME_MAX")
        except (OSError, ValueError) as e:
            raise SendmailTryQueueError("unable to get filesystem path/name limits: %s" % e)

        if len(self.queue_directory) > self.queue_directory_max_path:
            raise SendmailTryQueueError("directory name too long, %d > %d" % (
                len(self.queue_directory),
                self.queue_directory_max_path,
            ))

        if len(self.queue_name) > self.queue_directory_name_len:
            raise SendmailTryQueueError("queue name too long, %d > %d" % (
                len(self.queue_name),
                self.queue_directory_name_len,
            ))

    def QueueEmail(self, time_sent, sendmail_command, email_message, callback):
        path_root = pathlib.Path(self.queue_directory)

        path_root /= self.queue_name

        # TODO: exceptions
        email_parser = email.parser.BytesParser(policy=email.policy.default)
        envelope = email_parser.parsebytes(email_message)

        if "subject" not in envelope:
            raise SendmailTryQueueError("no subject stored in the email message")

        email_subject = re.sub(r"[\s]+", "_", envelope["subject"])

        email_subject = email_subject.replace("/", "-")

        # Seed the filename, in case two identical emails
        # are being queued at the exact same moment
        seed = int(random.uniform(1000, 9999))

        # Convert integers to strings to check their length
        time_sent = str(time_sent)
        seed = str(seed)

        def get_adjusted_length(max_len, time, seed, subject, ext):
            # NOTE: there are 2 separators in the final name
            anchors_len = len(time) + len(seed) + len(ext) + 2
            if anchors_len + len(subject) > max_len:
                logging.info("name too long, cutting the email subject to make room: %d", len(subject))

                if anchors_len >= max_len:
                    return None

                return max_len - anchors_len

            return len(subject)

        email_subject_length = get_adjusted_length(self.queue_directory_name_len, time_sent, seed,
                                                   email_subject, Defaults.EXT_EML)
        if email_subject_length is None:
            raise SendmailTryQueueError("cannot generate a suitable filename of size < %d" % self.queue_directory_name_len)

        shell_script_length = get_adjusted_length(self.queue_directory_name_len, time_sent, seed,
                                                  email_subject, Defaults.EXT_SH)
        if shell_script_length is None:
            raise SendmailTryQueueError("cannot generate a suitable filename of size < %d" % self.queue_directory_name_len)

        adjusted_length = min(email_subject_length, shell_script_length)

        path_email_message = "{}-{}-{}{}".format(time_sent, email_subject[:adjusted_length],
                                                 seed, Defaults.EXT_EML)
        path_shell_script = "{}-{}-{}{}".format(time_sent, email_subject[:adjusted_length],
                                                seed, Defaults.EXT_SH)

        path_email_message = path_root / path_email_message
        if len(str(path_email_message)) > self.queue_directory_max_path:
            raise SendmailTryQueueError("cannot generate a suitable filepath of size < %d"
                                        % self.queue_directory_max_path)

        path_shell_script = path_root / path_shell_script
        if len(str(path_shell_script)) > self.queue_directory_max_path:
            raise SendmailTryQueueError("cannot generate a suitable filepath of size < %d"
                                        % self.queue_directory_max_path)

        logging.debug("root directory: %s", self.queue_directory)
        logging.debug("queue storage directory: %s", path_root)
        logging.debug("path to the email message: %s", path_email_message)
        logging.debug("path to the sender script: %s", path_shell_script)

        callback(path_root,
                 path_email_message, path_shell_script,
                 sendmail_command, email_message)

    def ListQueue(self):
        path_queue = os.path.join(self.queue_directory, self.queue_name)

        logging.debug("recovering items from queue: %s", self.queue_name)

        try:
            with os.scandir(path_queue) as dir_queue:
                queue_items = sorted([x for x in dir_queue
                                     if x.is_file()
                                     and x.name.endswith(Defaults.EXT_EML)
                                     and re.match(r"\d+-", x.name)],
                                     key=lambda x: int(x.name.split('-')[0]))
        except OSError as e:
            raise SendmailTryQueueError("unable to read the queue directory: %s" % e)

        print("%s:" % self.queue_name)
        for idx_item, item in enumerate(queue_items):
            print("item: %s (%d / %d)" % (item.name, idx_item + 1, len(queue_items)))

    def FlushQueue(self, callback):
        path_queue = os.path.join(self.queue_directory, self.queue_name)

        logging.debug("recovering items from queue: %s", self.queue_name)

        try:
            with os.scandir(path_queue) as dir_queue:
                queue_items = sorted([x for x in dir_queue
                                     if x.is_file()
                                     and x.name.endswith(Defaults.EXT_EML)
                                     and re.match(r"\d+-", x.name)],
                                     key=lambda x: int(x.name.split('-')[0]))
        except OSError as e:
            raise SendmailTryQueueError("unable to read the queue directory: %s" % e)

        for idx_item, item in enumerate(queue_items):
            path_email_message = os.path.join(path_queue, item)
            path_shell_script = path_email_message[:-len(Defaults.EXT_EML)] + Defaults.EXT_SH

            logging.debug("item: %s (%d / %d)", item.name, idx_item + 1, len(queue_items))

            logging.debug("path to the email message: %s", path_email_message)
            logging.debug("path to the sender script: %s", path_shell_script)

            callback(path_email_message, path_shell_script, idx_item, len(queue_items))


class SendmailTryQueue(SendmailTryQueueBase):
    def __init__(self, queue_directory, queue_name):
        super().__init__(queue_directory, queue_name)

    def QueueEmail(self, time_sent, sendmail_command, email_message):
        def queue_email(path_root,
                        path_email_message, path_shell_script,
                        sendmail_command, email_message):
            try:
                path_root.parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise SendmailTryQueueError("unable to create queue directory: %s" % e)

            try:
                sendmail_command = shlex.join(sendmail_command)
            except ValueError as e:
                raise SendmailTryQueueError("unable to parse sendmail command: %s" % e)

            try:
                try:
                    fd = os.open(path_email_message, os.O_WRONLY | os.O_CREAT, mode=0o600)
                    with os.fdopen(fd, mode="wb") as fout:
                        fout.write(email_message)
                except OSError as e:
                    raise SendmailTryQueueError("unable to save email to the queue directory: %s" % e)

                try:
                    fd = os.open(path_shell_script, os.O_WRONLY | os.O_CREAT, mode=0o700)
                    with os.fdopen(fd, mode="w") as fout:
                        fout.write("#!/bin/sh\n")
                        fout.write(sendmail_command)
                except OSError as e:
                    raise SendmailTryQueueError("unable to save sendmail command to the queue directory: %s" % e)
            except KeyboardInterrupt:
                # Cleanup the files when interrupted
                if os.path.exists(path_email_message):
                    os.unlink(path_email_message)
                if os.path.exists(path_shell_script):
                    os.unlink(path_shell_script)

                raise SendmailTryQueueError("process interrupted as an email was being queued")

        super().QueueEmail(time_sent, sendmail_command, email_message, queue_email)

    def Sendmail(self, sendmail_command, email_message):
        try:
            logging.debug("executing command: %s", sendmail_command)

            p = subprocess.Popen(sendmail_command,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

            logging.debug("passing email to command: %s", email_message)

            stdout, stderr = p.communicate(email_message)
            exit_code = p.wait()

            if stdout:
                logging.debug("stdout: %s", stdout.decode("utf-8", "replace"))
            if stderr:
                logging.debug("stderr: %s", stderr.decode("utf-8", "replace"))

            if exit_code:
                logging.debug("the sendmail command exited with error code: %d", exit_code)
                return True
        except (OSError, subprocess.CalledProcessError) as e:
            raise SendmailTryQueueError("unable to run command: %s" % e)
        except KeyboardInterrupt:
            raise SendmailTryQueueError("process interrupted as an email was being sent")

        return False

    def FlushQueue(self):
        def flush_queue(path_email_message, path_shell_script, idx_item, nb_items):
            if not os.path.exists(path_email_message):
                raise SendmailTryQueueError("no such mail file: %s" % path_email_message)
            elif not os.path.exists(path_shell_script):
                raise SendmailTryQueueError("no such script file: %s" % path_shell_script)

            try:
                logging.debug("executing script: %s", path_shell_script)

                p = subprocess.Popen(path_shell_script,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)

                logging.debug("reading email message: %s", path_email_message)

                with open(path_email_message, "rb") as fin:
                    stdout, stderr = p.communicate(fin.read())

                exit_code = p.wait()
            except (OSError, subprocess.CalledProcessError) as e:
                raise SendmailTryQueueError("unable to run command: %s" % e)
            except KeyboardInterrupt:
                raise SendmailTryQueueError("process interrupted as an email was being sent")

            if stdout:
                logging.debug("stdout: %s", stdout.decode("utf-8", "replace"))
            if stderr:
                logging.debug("stderr: %s", stderr.decode("utf-8", "replace"))

            if exit_code:
                raise SendmailTryQueueError("the script exited with error code: %d" % exit_code)

            logging.debug("removing the files from the queue")

            os.unlink(path_shell_script)
            os.unlink(path_email_message)

        super().FlushQueue(flush_queue)


class SendmailTryQueueDryRun(SendmailTryQueueBase):
    def __init__(self, queue_directory, queue_name):
        super().__init__(queue_directory, queue_name)

    def QueueEmail(self, time_sent, sendmail_command, email_message):
        def queue_email(path_root,
                        path_email_message, path_shell_script,
                        sendmail_command, email_message):
            try:
                print("mkdir: %s" % path_root)
                print("write: %s" % path_email_message)
                print("write: %s" % path_shell_script)
            except KeyboardInterrupt:
                # Cleanup the files when interrupted
                if os.path.exists(path_email_message):
                    print("unlink: %s" % path_email_message)
                if os.path.exists(path_shell_script):
                    print("unlink: %s" % path_shell_script)

                raise SendmailTryQueueError("process interrupted as an email was being queued")

        super().QueueEmail(time_sent, sendmail_command, email_message, queue_email)

    def Sendmail(self, sendmail_cmd, email_message):
        print("exec: %s" % sendmail_cmd)
        print("write: %s" % email_message)

    def FlushQueue(self):
        def flush_queue(path_email_message, path_shell_script, idx_item, nb_items):
            try:
                print("exec: %s" % path_shell_script)
                print("read: %s" % path_email_message)
            except KeyboardInterrupt:
                raise SendmailTryQueueError("process interrupted as an email was being sent")
            print("unlink: %s" % path_shell_script)
            print("unlink: %s" % path_email_message)

        super().FlushQueue(flush_queue)


class CliOptions(argparse.Namespace):
    def __init__(self, args):
        parser = argparse.ArgumentParser(description="Sendmail TryQueue - Cache/queue emails that couldn't be sent")

        def type_queue_name(s):
            if re.match(r"[\w-]+$", s) is None:
                raise argparse.ArgumentTypeError("queue names should only contain alphanumerical/underscore/hyphen characters")

            return s

        parser.add_argument("-v", "--verbose", action="store_true", help="display information messages")
        parser.add_argument("-d", "--debug", action="store_true", help="display debug messages")
        parser.add_argument("-n", "--dry-run", action="store_true", help="do not modify the database, only print commands that would otherwise have been run")
        parser.add_argument("-D", "--queue-directory", default=Defaults.DIR_QUEUES, help="directory in which the queued emails will be stored")
        parser.add_argument("-Q", "--queue-name", default=Defaults.NAME_DEFAULT_QUEUE, type=type_queue_name, help="name of the default queue to append emails to, or flush emails from")

        subparsers = parser.add_subparsers(title="commands", dest="command", required=True)

        # TODO: -a to list all the queues, starting with the default one
        parser_list = subparsers.add_parser("list", help="list all the emails stored in the queue")
        # TODO: -a to list all the queues, starting with the default one
        parser_flush = subparsers.add_parser("flush", help="try to resend all the emails stored in the queue")

        parser_send = subparsers.add_parser("send", help="send am email, queueing it on failure")
        parser_send.add_argument("sendmail_command", nargs=argparse.REMAINDER)

        parser.parse_args(args, self)


def main(av):
    cli_options = CliOptions(av[1:])

    logging_level = logging.WARN
    if cli_options.debug:
        logging_level = logging.DEBUG
    elif cli_options.verbose:
        logging_level = logging.INFO
    logging.basicConfig(level=logging_level,
                        format="[%(asctime)s][%(levelname)s]: %(message)s")

    if cli_options.dry_run:
        logging.info("dry-run mode enabled, the commands will not be executed, but printed instead")

    try:
        sendmail_tryqueue = SendmailTryQueueDryRun if cli_options.dry_run else SendmailTryQueue
        sendmail_tryqueue = sendmail_tryqueue(cli_options.queue_directory, cli_options.queue_name)

        logging.debug("queue storage directory: %s", sendmail_tryqueue.queue_directory)
        logging.debug("name of the queue to use: %s", sendmail_tryqueue.queue_name)

        if cli_options.command == "send":
            logging.debug("reading the email message from the standard input")

            # FIXME: handle errors
            email_message = sys.stdin.buffer.read()

            # Grab a timestamp before attempting to send the email,
            # to ensure sending order in the queue later on
            time_sent = int(datetime.datetime.now().timestamp() * 1000)

            if sendmail_tryqueue.Sendmail([x.encode()
                                          for x in cli_options.sendmail_command],
                                          email_message):
                sendmail_tryqueue.QueueEmail(time_sent,
                                             cli_options.sendmail_command,
                                             email_message)
        elif cli_options.command == "list":
            sendmail_tryqueue.ListQueue()
        elif cli_options.command == "flush":
            sendmail_tryqueue.FlushQueue()
    except SendmailTryQueueError as e:
        logging.error("%s", e)
        return 1
    except KeyboardInterrupt:
        logging.info("process interrupted, quitting")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
