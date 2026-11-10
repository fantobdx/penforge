import os

from celery import Celery
from penforge import config

app = Celery(
    "pentest",
    broker=config.CELERY_BROKER_URL,
    backend=config.CELERY_RESULT_BACKEND,
)
app.conf.update(
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_queue_max_priority=10,
    task_default_priority=5,
)

app.autodiscover_tasks(["penforge.worker"])


def start_worker():
    app.worker_main(argv=["worker", "--pool=prefork", f"--concurrency={config.SCAN_WORKERS}", "-l", "info"])
