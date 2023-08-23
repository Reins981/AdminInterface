
import threading
import time
from kivy.clock import Clock
from queue import Queue, Empty


class StoppableThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()

    def stop(self):
        if self.is_alive():
            # set event to signal thread to terminate
            self.stop_event.set()
            # block calling thread until thread really has terminated
            try:
                print(f"{threading.current_thread().name} terminating..")
                self.join()
            except RuntimeError:
                pass


class Worker(StoppableThread):
    # executing tasks from a given tasks queue
    def __init__(self,
                 tasks,
                 task_name,
                 task_counter,
                 thread_results,
                 terminate_event=None,
                 schedule_clock=False):
        StoppableThread.__init__(self)
        self.tasks = tasks
        self.task_name = task_name
        self.terminate_condition = terminate_event.is_set() if terminate_event else False
        self.task_counter = task_counter
        self.thread_results = thread_results
        self.schedule_clock = schedule_clock

        # execute run()
        self.start()

    def run(self):
        error_msg = None
        error = False
        stopped = False
        while not self.terminate_condition:
            func, args, kwargs = self.tasks.get()
            try:
                Clock.schedule_once(lambda *st: func(*args, **kwargs)) if self.schedule_clock \
                    else func(*args, **kwargs)
            except Exception as e:
                error_msg = str(e)
                error = True
            finally:
                self.task_counter.set_task_counter()
                self.thread_results.add_result(False, error_msg) if error \
                    else self.thread_results.add_result(True, None)
                self.stop()
                stopped = True
                break

        if not stopped:
            self.stop()


class ThreadResults:
    def __init__(self):
        self.lock = threading.RLock()
        self._results = list()

    def add_result(self, status, error_message):
        with self.lock:
            self._results.append((status, error_message))

    @property
    def results(self):
        return self._results


class TaskCounter:
    def __init__(self):
        self.lock = threading.RLock()
        self.task_counter = 0

    def set_task_counter(self):
        with self.lock:
            self.task_counter += 1

    def get_task_counter(self):
        with self.lock:
            return self.task_counter


class ThreadPool:
    # Pool of threads consuming tasks from a queue
    def __init__(self,
                 num_threads=0,
                 task_name=None,
                 terminate_condition=None,
                 schedule_clock=False,
                 task_counter=None):

        self.num_threads = num_threads
        self.terminate_condition = terminate_condition
        self.schedule_clock = schedule_clock
        self.task_name = task_name
        self.tasks = Queue(self.num_threads)
        self.task_counter = task_counter or TaskCounter()
        self._thread_results = ThreadResults()

        for _ in range(self.num_threads):
            print(f"Starting Worker thread")
            try:
                Worker(
                    self.tasks,
                    self.task_name,
                    self.task_counter,
                    self._thread_results,
                    self.terminate_condition,
                    self.schedule_clock
                )
            except Exception as e:
                raise RuntimeError(str(e))

    def add_task(self, func, *args, **kwargs):
        # Add a task to the queue
        self.tasks.put((func, args, kwargs))

    def wait_completion(self):
        print('Waiting for task completion..')
        # Wait for completion of all the tasks in the queue
        while self.task_counter.get_task_counter() < self.num_threads:
            pass

        print("%d tasks completed" % self.num_threads)

    def thread_results(self):
        return self._thread_results.results
