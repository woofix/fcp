# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
bind = "0.0.0.0:9191"
workers = 1
worker_class = "gthread"
threads = 4
timeout = 120
graceful_timeout = 120
preload_app = False
accesslog = "-"
errorlog = "-"
capture_output = True
worker_tmp_dir = "/dev/shm"

def post_worker_init(worker):
    import ui
    ui.start_background_services()
