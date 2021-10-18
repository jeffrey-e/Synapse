import sched
import os
import time
from time import monotonic as _time
from datetime import datetime, timedelta
from collections import namedtuple
import logging
import threading
import heapq
import pickle
from shutil import copy, move, SameFileError

logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S')

class Event(namedtuple('Event', 'time, priority, action, argument, kwargs, attempts')):
    __slots__ = []

    def __eq__(s, o):
        return (s.time, s.priority) == (o.time, o.priority)

    def __lt__(s, o):
        return (s.time, s.priority) < (o.time, o.priority)

    def __le__(s, o):
        return (s.time, s.priority) <= (o.time, o.priority)

    def __gt__(s, o):
        return (s.time, s.priority) > (o.time, o.priority)

    def __ge__(s, o):
        return (s.time, s.priority) >= (o.time, o.priority)

_sentinel = object()

class EventScheduler(sched.scheduler):
    def __init__(self, queue_path, cfg, automation_config, modules, timefunc=_time, delayfunc=time.sleep, max_retries=3, retry_time=60):
        """Initialize a new instance, passing the time and delay
        functions"""
        self.logger = logging.getLogger(__name__)
        self.logger.info('Initiating Scheduler')
        self._lock = threading.RLock()
        self._running = False
        self._paused = False
        self.timefunc = timefunc
        self.delayfunc = delayfunc
        self.threads = []
        self._queue = []
        self._retry = []
        self.start_time = timefunc()
        self.max_retries = max_retries
        self.retry_time = retry_time
        self.cwd = os.getcwd()
        self.filepaths = {"q_path": os.path.join(self.cwd, queue_path)}
        self.cfg = cfg
        self.automation_config = automation_config
        self.modules = modules
        self.init_files()
        if not self.is_running():
            self.logger.info('Starting scheduler')
            self.scheduler_thread = threading.Thread(target=self.run)
            self.scheduler_thread.daemon = True
            self.scheduler_thread.start()

    def init_files(self):
        """This function sets up all the required files by calling ``init_file`` for each of them.
        If any of the files or folders do not exists, they will be created.
        This function also defines the names of the files.
        """
        queue_path = os.path.basename(self.filepaths["q_path"])
        filename, extension = queue_path.split('.')

        self.filepaths["bkp_path"] = os.path.join(self.cwd, f"backups/{filename}.bkp")
        self.filepaths["tmp_path"] = os.path.join(self.cwd, f"backups/{filename}.tmp")
        self.filepaths["retry_path"] = os.path.join(self.cwd, f"{filename}_retry.pkl")
        self.filepaths["retry_bkp_path"] = os.path.join(self.cwd, f"backups/{filename}_retry.bkp")
        self.filepaths["retry_tmp_path"] = os.path.join(self.cwd, f"backups/{filename}_retry.tmp")

        self.init_file(self.filepaths["q_path"])
        self.init_file(self.filepaths["retry_path"])
        backup_dir = os.path.join(self.cwd, "backups/")
        if os.path.exists(backup_dir) is False:
            os.mkdir(backup_dir)

    def init_file(self, path):
        """ Tries to create a file, if the file already exists, it is restored to be compatible
        with this instance of the scheduler.

        : param str path: a string describing the (full) path to the queue file.
        """
        try:
            with open(path, "x") as file:
                pass
        except FileExistsError:
            if "pkl" in path:
                self.restore_queue(path)
        return path

    def restore_queue(self, path):
        """ This function reads and recalculates the timestamps for all events in the queue if necessary.
        It checks the timestamp that is added to the first line of every queue file,
        and compares it to the current monotonic time.
        If the current time value is lower than the retrieved timestamp, all timestamps are refactored
        to be compatible with the new monotonic time.

        The refactoring is done by subtracting the old monotonic time from the timestamp,
        and then adding the new monotonic time, translating it while preserving differences.
        An event that would be executed in 2 minutes will still be executed in two minutes.
        This does mean that time does not keep running when the scheduler is offline.
        i.e.: if an event would be executed two minutes after shutdown, it will be executed
        2 minutes after the next startup.

        : param str path: a string describing the (full) path to the queue file.
        """
        heap = []
        start_time = None
        with open(path, 'rb') as file:
            while True:
                try:
                    item = (pickle.load(file))
                    if isinstance(item, Event):
                        self.logger.debug("Restoring event: {}".format(item))
                        heap.append(item)
                    elif type(item) is float:
                        start_time = item
                except EOFError:
                    break
        current_time = self.timefunc()
        if "retry.pkl" in path:
            self._retry = heap
        elif "queue.pkl" in path:
            self._queue = heap
        if start_time and current_time < start_time:
            self.logger.info("Detected possible system restart, recalculating execution times")
            updated_heap = []
            for event in heap:
                time, priority, action, argument, kwargs, attempts = event
                time_until_execute = time - start_time
                new_event_time = current_time + time_until_execute
                updated_heap.append(Event(time, priority, action, argument, kwargs, attempts))
            if "retry.pkl" in path:
                self.filepaths["retry_path"] = path  # Create dict entry as this might not exist yet.
                self.write_heap(updated_heap, True, backup=False)
                self._retry = updated_heap
            elif "queue.pkl" in path:
                self.write_heap(updated_heap, backup=False)
                self._queue = updated_heap
        self.logger.info("Finished restoring queue")

    def remove_files(self):
        """ Removes all files that are created by the scheduler. This should not be used in normal operations.
        """
        for key in self.filepaths:
            os.remove(self.filepaths[key])

    def reset_files(self):
        """ Deletes and reinitializes all required files.
        """
        self.remove_files()
        self.init_files()

    def action_wrapper(self, event):
        """ This wrapper ensures that failed events have their exceptions caught, which then triggers a rescheduling
        in an alternative retry queue. The maximum amount of retries can be set on the initialization of the scheduler.

        : param Event event: an object representing a scheduled event.
        """
        time, priority, action, argument, kwargs, attempts = event
        automators = self.modules['automators'][action['module']].Automators(self.cfg, self.automation_config)
        action = getattr(automators, '{}'.format(action['function']))
        try:
            if type(kwargs) is dict:
                action(*argument, **kwargs)
            else:
                action(*argument)
        except Exception as e:
            # Behavior is currently not defined for each automator.
            
            # time += self.retry_time
            # attempts += 1
            # if attempts <= self.max_retries:
            #     event = Event(time, priority, action, argument, kwargs, attempts)
            #     with self._lock:
            #         heapq.heappush(self._retry, event)
            #         self.write_heap(self._retry, retry=True)
            #         self.logger.info(f"Rescheduled {event} after this exception occurred: ({e})")
            # else:
            #     self.logger.info(f"Event failed more than three times, deleting: {event} ")
            self.logger.error(f"Event {event} failed with exception", exc_info=True)

    def enterabs(self, time, priority, action, argument=(), kwargs={}):
        """Enter a new event in the queue at an absolute time.

        Returns an ID for the event which can be used to remove it,
        if necessary.

        """
        if kwargs is _sentinel:
            kwargs = {}
        event = Event(time, priority, action, argument, kwargs, 0)
        with self._lock:
            heapq.heappush(self._queue, event)
            self.write_heap(self._queue)
        return event  # The ID

    def schedule_periodic_event(self, actionfunc, arguments, time_step, n_step):
        """
        This function schedules an event 'n_step' times every 'time_step' seconds. \n
        It requires a function as input, while the arguments MUST be
        contained in a list.

        :param actionfunc: callable (or a textual reference to one) to run at the given time.

        :param list|tuple arguments: list of positional arguments to call func with.

        :param int time_step: time in seconds untill the event should be executed.

        :paramt int n_step: amount of times that the event will be scheduled.
        """
        for i in range(n_step):
            self.enter(time_step * (i + 1), 1, actionfunc, argument=arguments)
            self.logger.info(f"Periodically scheduled {actionfunc} in {time_step * (i + 1)} " +
                              f"seconds with arguments:\n {arguments}")

    def schedule_event(self, actionfunc, arguments, date):
        """
        This function schedules an event once at the specified date. \n
        It requires a function as input, while the arguments MUST be
        contained in a list.

        :param actionfunc: callable (or a textual reference to one) to run at the given time.

        :param list|tuple arguments: list of positional arguments to call func with.

        :param datetime date: when to run the job.
        """
        parsed_date = self.parse_time(date)
        time_step = self.get_time_difference(parsed_date)
        if time_step < 0:
            self.logger.warning("Target time is in the past, please pick a time that is in the future.")
            return(-1)
        if time_step >= 0:
            self.enter(time_step, 1, actionfunc, argument=arguments)
            self.logger.info(f"Scheduled {actionfunc} in {time_step} seconds with arguments:\n {arguments}")

    def schedule_after_time(self, module_name, function_name, arguments, days=0, hours=0, minutes=0, n_step=1):
        """
        Schedule an event after a set amount of days, hours and/or minutes.

        :param actionfunc: callable (or a textual reference to one) to run at the given time.

        :param list|tuple arguments: list of positional arguments to call func with.

        :param int days: amount of days until the event is executed.

        :param int hours: amount of hours until the event is executed.

        :param int minutes: amount of minutes until the event is executed.
        """
        diff = timedelta(days=days, hours=hours, minutes=minutes)
        diff_seconds = diff.total_seconds()

        actionfunc = {"module": module_name, "function": function_name}

        for i in range(n_step):
            self.enter(diff_seconds * (i + 1), 1, actionfunc, argument=arguments)
            self.logger.info(f"Periodically scheduled {actionfunc} in {diff_seconds * (i + 1)} " +
                             f"seconds with arguments:\n {arguments}")
        self.logger.info(f"Scheduled {actionfunc} in after {diff_seconds} seconds with arguments:\n {arguments}")

    def get_time_difference(self, target_time):
        """
        Takes a datetime object as input and returns the difference
        in time from now in seconds.

        :param datetime target_time: a datetime object representing the target time.
        """
        diff = target_time - datetime.now()
        diff_seconds = diff.total_seconds()
        self.logger.debug(f"difference = {diff}")

        return(diff_seconds)

    def parse_time(self, time_string):
        """
        Takes a formatted string as input and converts it to a datetime object
        The time must be formatted as follows:

            "%Y-%m-%d %H:%M:%S"

        :param str time_string: string in earlier mentioned time-format.
        """
        return(datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S"))

    def keeptheservicerunning(self, arguments):
        """
        (Deprecated) The only purpose of this function is to pass, in order to keep the
        scheduler from running out of tasks and shutting down.
        """
        pass

    def is_running(self):
        """
        The only purpose of this function is to pass, in order to keep the
        scheduler from running out of tasks and shutting down.
        """
        return self._running

    def pause_scheduler(self):
        """
        Sets the ``self._paused`` flag to True and waits for all worker threads to finish.
        The scheduler will wait until the ``self._paused`` flag is set to True.
        """
        self._paused = True
        self.logger.info("Waiting for threads to finish")
        for action_thread in self.threads:
            while action_thread.isAlive():
                action_thread.join()

    def terminate_scheduler(self, thread):
        """
        Sets the ``self._running`` flag to False and waits for all threads to finish.
        A new thread will have to be created to restart the scheduler.

        :param Thread thread: the main thread used to run the self.run() function.
        """
        self._running = False
        self.logger.info("Waiting for threads to finish")
        for action_thread in self.threads:
            while action_thread.isAlive():
                action_thread.join()
        while thread.isAlive():
            thread.join()
        self.logger.info("Threads shut down.")

    def get_heap(self, path):
        """ Reads the pickle file entry by entry, reconstructing the queue.

        : param str path: a string describing the (full) path to the queue file.
        """
        heap = []
        with open(path, 'rb') as file:
            while True:
                try:
                    item = (pickle.load(file))
                    if isinstance(item, Event):
                        heap.append(item)
                except EOFError:
                    break
        return(heap)

    def write_heap(self, heap, retry=False, backup=True):
        """ Writes the queue to a pickle file, item by item.
        It has options to enable backup creation and to handle the retry queue
        : param List heap: a heapified list containing scheduled Event objects
        : param bool retry: causes retry filepaths to be used when enabled.
        : param bool backup: enables backup creation when enabled.
        """
        if retry:
            if backup:
                self.backup(retry)
            with open(self.filepaths["retry_path"], 'wb') as file:
                pickle.dump(self.timefunc(), file)
                for event in heap:
                    pickle.dump(event, file)
        else:
            if backup:
                self.backup(retry)
            with open(self.filepaths["q_path"], 'wb') as file:
                pickle.dump(self.timefunc(), file)
                for event in heap:
                    pickle.dump(event, file)

    def backup(self, retry=False):
        """ Backs up the main and retry queue by moving the contents to a backup file.
        It will not perform the backup operation if the queue and the backup are identical.

        :param bool retry: causes retry filepaths to be used when enabled.
        """
        if retry:
            try:
                move(self.filepaths["retry_path"], self.filepaths["retry_bkp_path"])
            except SameFileError:
                pass

        else:
            try:
                move(self.filepaths["q_path"], self.filepaths["bkp_path"])
            except SameFileError:
                # if the file is exactly the same, no copying is needed.
                pass

    def run(self, blocking=True):
        """
        The run function has been overriden to never stop, and threading has been added to the task.
        For more detail check the documentation for sched.run()

        :param bool blocking: disables blocking when set to false. This will currently break the scheduler.
        """
        # localize variable access to minimize overhead
        # and to improve thread safety
        retrying = False
        lock = self._lock
        self._running = True
        delayfunc = self.delayfunc
        timefunc = self.timefunc
        pop = heapq.heappop
        queue = self._queue
        retry = self._retry
        while self._running:
            if not self._paused:
                with lock:
                    if not (queue or retry):
                        self._running = False
                        break
                    elif (queue and not retry):
                        event = queue[0]
                    elif (queue and retry):
                        if retry[0] >= queue[0]:
                            event = queue[0]
                        else:
                            event = retry[0]
                            retrying = True
                    elif (not queue and retry):
                        event = retry[0]
                        retrying = True
                    time = event.time
                    now = timefunc()
                    if time > now:
                        delay = True
                    else:
                        delay = False
                        if retrying:
                            pop(retry)
                            self.write_heap(retry, retrying)
                            retrying = False
                        else:
                            pop(queue)
                            self.write_heap(queue, retrying)
                if delay:
                    if not blocking:
                        return time - now
                    if (time - now) > 10:
                        delayfunc(10)
                else:
                    # Implement some kind of threading.excepthook implementation to catch bad executions
                    action_thread = threading.Thread(target=self.action_wrapper, args=[event], kwargs={})
                    self.threads.append(action_thread)
                    action_thread.start()
                    self.logger.info(f"Starting task: target = {event.action}, " +
                                     f"args={event.argument}, kwargs={event.kwargs}")
                    delayfunc(0)   # Let other threads run
